package build

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	packageurl "github.com/package-url/packageurl-go"
	bolt "go.etcd.io/bbolt"
	"ncsc-trivy-db/internal/audit"
	"ncsc-trivy-db/internal/csaf"
	"ncsc-trivy-db/internal/mirror"
)

func fixtureMirror(t *testing.T, complete bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ncsc.db")
	db, e := mirror.Open(path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	files, e := filepath.Glob("../../testdata/ncsc/*.json.gz")
	if e != nil || len(files) == 0 {
		t.Fatal("missing fixtures", e)
	}
	e = db.Update(func(tx *bolt.Tx) error {
		var index []string
		for _, n := range []string{"documents", "revisions", "inventory", "metadata"} {
			if _, e := tx.CreateBucket([]byte(n)); e != nil {
				return e
			}
		}
		for _, file := range files {
			b, e := os.ReadFile(file)
			if e != nil {
				return e
			}
			raw, e := mirror.Decompress(b)
			if e != nil {
				return e
			}
			d, e := csaf.Decode(raw)
			if e != nil {
				return e
			}
			cve := d.Document.Tracking.ID
			key := cve[4:8] + "/" + filepath.Base(file[:len(file)-3])
			index = append(index, key)
			for _, n := range []string{"inventory", "revisions"} {
				if e = tx.Bucket([]byte(n)).Put([]byte(key), []byte("fixture")); e != nil {
					return e
				}
			}
			if e = tx.Bucket([]byte("documents")).Put([]byte(key), b); e != nil {
				return e
			}
		}
		s := mirror.Snapshot{Source: mirror.Directory, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Indexed: len(files), Selected: len(files), Available: len(files), Complete: complete}
		for k, v := range map[string]string{"index.txt": strings.Join(index, "\n") + "\n", "changes.csv": "test fixture revisions", "provider-metadata.json": `{"distributions":[{"directory_url":"https://vulnerabilities.ncsc.nl/csaf/v2/"}]}`} {
			if e := tx.Bucket([]byte("metadata")).Put([]byte(k), []byte(v)); e != nil {
				return e
			}
		}
		return putJSON(tx.Bucket([]byte("metadata")), "snapshot", s)
	})
	if e != nil {
		t.Fatal(e)
	}
	return path
}

func TestBuildAndRoundTrip(t *testing.T) {
	m := fixtureMirror(t, true)
	out := filepath.Join(t.TempDir(), "build")
	r, e := Build(context.Background(), Options{Mirror: m, Output: out, Validity: 24 * time.Hour})
	if e != nil {
		t.Fatal(e)
	}
	if !r.Complete || r.Documents != 6 || r.Vulnerabilities != 6 || r.Advisories == 0 || r.VulnerabilitiesWithMatches == 0 {
		t.Fatalf("bad report: %+v", r)
	}
	if r.ProductObservations != r.SupportedObservations+r.CandidateObservations+r.IgnoredObservations+sumReasons(r.UnmappedReasons) {
		t.Fatal("product observation outcomes overlap or are missing")
	}
	var b bytes.Buffer
	if e = ExportCSAF(filepath.Join(out, "db", "trivy.db"), "2021/cve-2021-44228.json", &b); e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile("../../testdata/ncsc/cve-2021-44228.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := mirror.Decompress(original)
	if e != nil || !bytes.Equal(b.Bytes(), raw) {
		t.Fatal("CSAF round trip was not byte-for-byte exact", e)
	}
	stale := filepath.Join(out, "verification.json")
	if e = os.WriteFile(stale, []byte(`{"old":true}`), 0644); e != nil {
		t.Fatal(e)
	}
	if r, e = Build(context.Background(), Options{Mirror: m, Output: out + string(os.PathSeparator), Validity: 48 * time.Hour}); e != nil {
		t.Fatal("rebuild failed", e)
	}
	if _, e = os.Stat(stale); !os.IsNotExist(e) {
		t.Fatal("rebuild retained stale verification results", e)
	}
	metadata, e := os.ReadFile(filepath.Join(out, "db", "metadata.json"))
	if e != nil {
		t.Fatal(e)
	}
	var meta Metadata
	if e = json.Unmarshal(metadata, &meta); e != nil {
		t.Fatal(e)
	}
	if !meta.NextUpdate.Equal(r.Snapshot.StartedAt.Add(48 * time.Hour)) {
		t.Fatal("rebuild did not publish new metadata", meta)
	}
	checked, e := audit.Check(context.Background(), m, filepath.Join(out, "db", "trivy.db"))
	if e != nil {
		t.Fatal(e)
	}
	if !checked.Complete || checked.Documents != r.Documents || checked.Advisories != r.Advisories {
		t.Fatalf("bad audit report: %+v", checked)
	}
}

func TestFailedRebuildPreservesOutput(t *testing.T) {
	m := fixtureMirror(t, true)
	out := filepath.Join(t.TempDir(), "build")
	if _, err := Build(context.Background(), Options{Mirror: m, Output: out, Validity: time.Hour}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(out, "db", "trivy.db"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := mirror.Open(m, false)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("documents")).Delete([]byte("2021/cve-2021-44228.json"))
	})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Build(context.Background(), Options{Mirror: m, Output: out, Validity: time.Hour}); err == nil {
		t.Fatal("rebuild accepted missing document")
	}
	after, err := os.ReadFile(filepath.Join(out, "db", "trivy.db"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed rebuild changed previous database", err)
	}
	entries, err := os.ReadDir(filepath.Dir(out))
	if err != nil || len(entries) != 1 || entries[0].Name() != "build" {
		t.Fatal("failed rebuild left temporary output", entries, err)
	}
}

func TestPublishRestoresOutputOnFailure(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "build")
	if err := os.Mkdir(out, 0755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(out, "previous")
	if err := os.WriteFile(marker, []byte("previous build"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := publish(filepath.Join(root, "missing-stage"), out); err == nil {
		t.Fatal("published missing stage")
	}
	if contents, err := os.ReadFile(marker); err != nil || string(contents) != "previous build" {
		t.Fatal("previous output was not restored", err)
	}
}

func TestAuditRejectsTampering(t *testing.T) {
	for _, name := range []string{"source-bytes", "extra-vulnerability", "foreign-source"} {
		t.Run(name, func(t *testing.T) {
			m := fixtureMirror(t, true)
			out := filepath.Join(t.TempDir(), "build")
			if _, e := Build(context.Background(), Options{Mirror: m, Output: out, Validity: time.Hour}); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(out, "db", "trivy.db")
			db, e := mirror.Open(path, false)
			if e != nil {
				t.Fatal(e)
			}
			e = db.Update(func(tx *bolt.Tx) error {
				switch name {
				case "source-bytes":
					return tx.Bucket([]byte("ncsc-csaf")).Put([]byte("2021/cve-2021-44228.json"), []byte("tampered"))
				case "extra-vulnerability":
					return tx.Bucket([]byte("vulnerability")).Put([]byte("CVE-2026-999999"), []byte(`{}`))
				case "foreign-source":
					return putJSON(tx.Bucket([]byte("data-source")), "npm::foreign", DataSource{"nvd", "NVD", "https://nvd.nist.gov"})
				}
				return nil
			})
			db.Close()
			if e != nil {
				t.Fatal(e)
			}
			if _, e = audit.Check(context.Background(), m, path); e == nil {
				t.Fatal("audit accepted tampered build")
			}
		})
	}
}

func TestAuditRejectsCandidateTampering(t *testing.T) {
	m := fixtureMirror(t, true)
	db, e := mirror.Open(m, false)
	if e != nil {
		t.Fatal(e)
	}
	compressed, e := os.ReadFile("../../testdata/ncsc/conversion/cve-2022-0563.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	e = db.Update(func(tx *bolt.Tx) error {
		key := []byte("2022/cve-2022-0563.json")
		for _, name := range []string{"documents", "inventory", "revisions"} {
			value := []byte("fixture")
			if name == "documents" {
				value = compressed
			}
			if err := tx.Bucket([]byte(name)).Put(key, value); err != nil {
				return err
			}
		}
		meta := tx.Bucket([]byte("metadata"))
		index := append(append([]byte{}, meta.Get([]byte("index.txt"))...), append(key, '\n')...)
		if err := meta.Put([]byte("index.txt"), index); err != nil {
			return err
		}
		var s mirror.Snapshot
		if err := json.Unmarshal(meta.Get([]byte("snapshot")), &s); err != nil {
			return err
		}
		s.Indexed++
		s.Selected++
		s.Available++
		return putJSON(meta, "snapshot", s)
	})
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	cache := filepath.Join(t.TempDir(), "cache")
	if _, e = Build(context.Background(), Options{Mirror: m, Output: cache, Validity: time.Hour}); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(cache, "db", "trivy.db")
	if _, e = audit.Check(context.Background(), m, path); e != nil {
		t.Fatal(e)
	}
	db, e = mirror.Open(path, false)
	if e != nil {
		t.Fatal(e)
	}
	e = db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte("ncsc-candidates"))
		return root.ForEach(func(k, v []byte) error {
			b := root.Bucket(k)
			if b == nil {
				return nil
			}
			cursor := b.Cursor()
			key, _ := cursor.First()
			if key == nil {
				return nil
			}
			return b.Put(key, []byte(`{"tampered":true}`))
		})
	})
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = audit.Check(context.Background(), m, path); e == nil {
		t.Fatal("tampered candidate passed audit")
	}
}

func TestPartialAndStaleRefused(t *testing.T) {
	m := fixtureMirror(t, false)
	out := filepath.Join(t.TempDir(), "build")
	if _, e := Build(context.Background(), Options{Mirror: m, Output: out, Validity: time.Hour}); e == nil {
		t.Fatal("partial mirror accepted")
	}
	db, e := mirror.Open(m, false)
	if e != nil {
		t.Fatal(e)
	}
	e = db.Update(func(tx *bolt.Tx) error {
		var s mirror.Snapshot
		if e := json.Unmarshal(tx.Bucket([]byte("metadata")).Get([]byte("snapshot")), &s); e != nil {
			return e
		}
		s.Complete = true
		if e := putJSON(tx.Bucket([]byte("metadata")), "snapshot", s); e != nil {
			return e
		}
		return tx.Bucket([]byte("documents")).Delete([]byte("2021/cve-2021-44228.json"))
	})
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Build(context.Background(), Options{Mirror: m, Output: out, Validity: time.Hour}); e == nil {
		t.Fatal("missing document accepted")
	}
	if _, e = os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("failed build published output")
	}
}

func TestStockTrivy(t *testing.T) {
	trivy, e := exec.LookPath("trivy")
	if e != nil {
		t.Skip("trivy is not installed")
	}
	m := fixtureMirror(t, true)
	out := filepath.Join(t.TempDir(), "cache")
	if _, e = Build(context.Background(), Options{Mirror: m, Output: out, Validity: 24 * time.Hour}); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name, purl, cve string
		affected        bool
		distro          string
	}{
		{"log4j-affected", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "CVE-2021-44228", true, ""},
		{"log4j-safe", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", "CVE-2021-44228", false, ""},
		{"python-affected", "pkg:pypi/restrictedpython@7.4", "CVE-2025-22153", true, ""},
		{"python-safe", "pkg:pypi/restrictedpython@8.0", "CVE-2025-22153", false, ""},
		{"debian-affected", "pkg:deb/debian/apache-log4j2@2.14.1-1?distro=bookworm", "CVE-2021-44228", true, "debian/12"},
		{"debian-safe", "pkg:deb/debian/apache-log4j2@2.15.0-1?distro=bookworm", "CVE-2021-44228", false, "debian/12"},
		{"debian-other-release", "pkg:deb/debian/apache-log4j2@2.14.1-1?distro=bullseye", "CVE-2021-44228", false, "debian/11"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pu, e := packageurl.FromString(tc.purl)
			if e != nil {
				t.Fatal(e)
			}
			group := pu.Namespace
			if pu.Type == "deb" {
				group = ""
			}
			sbom := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []any{map[string]any{"type": "library", "name": pu.Name, "group": group, "version": pu.Version, "purl": tc.purl}}}
			file := filepath.Join(t.TempDir(), "sbom.json")
			if e := writeJSON(file, sbom); e != nil {
				t.Fatal(e)
			}
			args := []string{"sbom", "--cache-dir", out, "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--skip-version-check", "--disable-telemetry", "--format", "json", file}
			if tc.distro != "" {
				args = append(args, "--distro", tc.distro)
			}
			cmd := exec.Command(trivy, args...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			b, e := cmd.Output()
			if e != nil {
				t.Fatalf("trivy: %v\n%s", e, stderr.String())
			}
			var report struct {
				Results []struct {
					Vulnerabilities []struct {
						VulnerabilityID, Severity string
						DataSource                DataSource
					}
				}
			}
			if e = json.Unmarshal(b, &report); e != nil {
				t.Fatal(e)
			}
			found := false
			for _, r := range report.Results {
				for _, v := range r.Vulnerabilities {
					if v.VulnerabilityID == tc.cve {
						found = true
						if v.DataSource.ID != csaf.SourceID {
							t.Fatalf("wrong data source: %+v", v)
						}
						if v.Severity == "UNKNOWN" {
							t.Fatal("severity lost")
						}
					}
				}
			}
			if found != tc.affected {
				t.Fatalf("affected=%t, wanted %t\n%s\n%s", found, tc.affected, b, stderr.String())
			}
		})
	}
}
