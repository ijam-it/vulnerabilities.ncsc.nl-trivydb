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

	bolt "go.etcd.io/bbolt"
	"ncsc-trivy-db/internal/csaf"
	"ncsc-trivy-db/internal/mirror"
	"ncsc-trivy-db/internal/scan"
)

func TestStockTrivyUnknownRangeDoesNotMatch(t *testing.T) {
	if _, e := exec.LookPath("trivy"); e != nil {
		t.Skip("trivy is not installed")
	}
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
			value := []byte("test")
			if name == "documents" {
				value = compressed
			}
			if err := tx.Bucket([]byte(name)).Put(key, value); err != nil {
				return err
			}
		}
		var s mirror.Snapshot
		if err := json.Unmarshal(tx.Bucket([]byte("metadata")).Get([]byte("snapshot")), &s); err != nil {
			return err
		}
		s.Indexed++
		s.Selected++
		s.Available++
		return putJSON(tx.Bucket([]byte("metadata")), "snapshot", s)
	})
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	cache := filepath.Join(t.TempDir(), "cache")
	r, e := Build(context.Background(), Options{Mirror: m, Output: cache, Validity: time.Hour})
	if e != nil {
		t.Fatal(e)
	}
	if r.CandidateObservations == 0 {
		t.Fatal("candidate missing")
	}
	for _, tc := range []struct {
		version, distro, release string
	}{{"1.0-1", "bookworm", "12"}, {"9.9-1", "bookworm", "12"}, {"1.0-1", "bullseye", "11"}} {
		t.Run(tc.distro+"/"+tc.version, func(t *testing.T) {
			sbom := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []any{map[string]any{"type": "library", "name": "util-linux", "version": tc.version, "purl": "pkg:deb/debian/util-linux@" + tc.version + "?distro=" + tc.distro}}}
			path := filepath.Join(t.TempDir(), "sbom.json")
			if e := writeJSON(path, sbom); e != nil {
				t.Fatal(e)
			}
			var stdout, stderr bytes.Buffer
			if e := scan.Run(context.Background(), "sbom", cache, []string{"--format", "json", "--distro", "debian/" + tc.release, "--exit-code", "1", path}, nil, &stdout, &stderr); e != nil {
				t.Fatal(e, stderr.String())
			}
			var result struct {
				Results []struct {
					Vulnerabilities []struct{ VulnerabilityID string }
				}
			}
			if e := json.Unmarshal(stdout.Bytes(), &result); e != nil {
				t.Fatal(e, stdout.String(), stderr.String())
			}
			for _, rs := range result.Results {
				for _, v := range rs.Vulnerabilities {
					if v.VulnerabilityID == "CVE-2022-0563" {
						t.Fatal("unspecified affected versions produced a scan finding")
					}
				}
			}
		})
	}
}

func TestStockTrivyAlpineConversion(t *testing.T) {
	trivy, err := exec.LookPath("trivy")
	if err != nil {
		t.Skip("trivy is not installed")
	}
	m := fixtureMirror(t, true)
	db, err := mirror.Open(m, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, cve := range []string{"cve-2021-28706", "cve-2024-58251", "cve-2024-12797", "cve-2025-29087"} {
		compressed, err := os.ReadFile(filepath.Join("../../testdata/ncsc/conversion", cve+".json.gz"))
		if err != nil {
			t.Fatal(err)
		}
		err = db.Update(func(tx *bolt.Tx) error {
			key := []byte(cve[4:8] + "/" + cve + ".json")
			for _, name := range []string{"documents", "inventory", "revisions"} {
				value := []byte("test")
				if name == "documents" {
					value = compressed
				}
				if e := tx.Bucket([]byte(name)).Put(key, value); e != nil {
					return e
				}
			}
			var s mirror.Snapshot
			if e := json.Unmarshal(tx.Bucket([]byte("metadata")).Get([]byte("snapshot")), &s); e != nil {
				return e
			}
			s.Indexed++
			s.Selected++
			s.Available++
			return putJSON(tx.Bucket([]byte("metadata")), "snapshot", s)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	p := csaf.Product{ID: "bounded", Name: "vers:unknown/>=1.36.1-r20|<1.36.1-r31"}
	p.Helper.PURL = "pkg:apk/alpine/busybox?distro=3.20"
	d := csaf.Document{}
	d.Document.CSAFVersion = "2.0"
	d.Document.Tracking.ID = "CVE-2026-1234"
	d.ProductTree.FullProductNames = []csaf.Product{p}
	d.Vulnerabilities = []csaf.Vulnerability{{CVE: "CVE-2026-1234", ProductStatus: map[string][]string{"known_affected": {"bounded"}}}}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := mirror.Compress(raw)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		key := []byte("2026/cve-2026-1234.json")
		for _, name := range []string{"documents", "inventory", "revisions"} {
			value := []byte("test")
			if name == "documents" {
				value = compressed
			}
			if e := tx.Bucket([]byte(name)).Put(key, value); e != nil {
				return e
			}
		}
		var s mirror.Snapshot
		if e := json.Unmarshal(tx.Bucket([]byte("metadata")).Get([]byte("snapshot")), &s); e != nil {
			return e
		}
		s.Indexed++
		s.Selected++
		s.Available++
		return putJSON(tx.Bucket([]byte("metadata")), "snapshot", s)
	})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	cache := filepath.Join(t.TempDir(), "cache")
	if _, err = Build(context.Background(), Options{Mirror: m, Output: cache, Validity: time.Hour}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		label, name, source, version, distro, cve string
		want                                      bool
	}{
		{"xen-affected", "xen", "xen", "4.13.4-r2", "alpine/3.12", "CVE-2021-28706", true},
		{"xen-fixed", "xen", "xen", "4.13.4-r3", "alpine/3.12", "CVE-2021-28706", false},
		{"xen-other-release", "xen", "xen", "4.13.4-r2", "alpine/3.20", "CVE-2021-28706", false},
		{"busybox-affected", "busybox", "busybox", "1.36.1-r29", "alpine/3.20", "CVE-2024-58251", true},
		{"busybox-fixed", "busybox", "busybox", "1.36.1-r31", "alpine/3.20", "CVE-2024-58251", false},
		{"busybox-other-release", "busybox", "busybox", "1.36.1-r29", "alpine/3.18", "CVE-2024-58251", false},
		{"bounded-below-lower", "busybox", "busybox", "1.36.1-r19", "alpine/3.20", "CVE-2026-1234", false},
		{"bounded-inside", "busybox", "busybox", "1.36.1-r29", "alpine/3.20", "CVE-2026-1234", true},
		{"libcrypto-affected", "libcrypto3", "openssl", "3.3.2-r1", "alpine/3.20", "CVE-2024-12797", true},
		{"libssl-affected", "libssl3", "openssl", "3.3.2-r1", "alpine/3.20", "CVE-2024-12797", true},
		{"libcrypto-fixed", "libcrypto3", "openssl", "3.3.3-r0", "alpine/3.20", "CVE-2024-12797", false},
		{"holdout-sqlite-affected", "sqlite-libs", "sqlite", "3.45.3-r1", "alpine/3.20", "CVE-2025-29087", true},
		{"holdout-sqlite-fixed", "sqlite-libs", "sqlite", "3.45.3-r2", "alpine/3.20", "CVE-2025-29087", false},
		{"holdout-sqlite-below-lower", "sqlite-libs", "sqlite", "3.43.0-r0", "alpine/3.20", "CVE-2025-29087", false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			props := []any{map[string]string{"name": "aquasecurity:trivy:PkgType", "value": "alpine"}, map[string]string{"name": "aquasecurity:trivy:SrcName", "value": tc.source}, map[string]string{"name": "aquasecurity:trivy:SrcVersion", "value": tc.version}}
			sbom := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []any{map[string]any{"type": "library", "name": tc.name, "version": tc.version, "purl": "pkg:apk/alpine/" + tc.name + "@" + tc.version + "?distro=3.20.3", "properties": props}}}
			path := filepath.Join(t.TempDir(), "sbom.json")
			if e := writeJSON(path, sbom); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(trivy, "sbom", "--cache-dir", cache, "--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update", "--offline-scan", "--skip-version-check", "--disable-telemetry", "--format", "json", "--distro", tc.distro, path)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			out, e := cmd.Output()
			if e != nil {
				t.Fatal(e, stderr.String())
			}
			got := strings.Contains(string(out), `"VulnerabilityID": "`+tc.cve+`"`)
			if got != tc.want {
				t.Fatalf("got %t, want %t: %s\n%s", got, tc.want, out, stderr.String())
			}
		})
	}
}

// These synthetic records test the schema contract for ecosystems not present
// in our small real-data fixtures. They are not distributed as vulnerability data.
func TestStockTrivyEcosystems(t *testing.T) {
	trivy, e := exec.LookPath("trivy")
	if e != nil {
		t.Skip("trivy is not installed")
	}
	for _, tc := range []struct{ typ, name, group, purl, ranges, affected, safe string }{
		{"npm", "example-package", "", "pkg:npm/example-package", "vers:npm/>=1.2.0|<2.0.0", "1.2.3", "2.0.0"},
		{"pip", "example-package", "", "pkg:pypi/example-package", "vers:pypi/>=1.0|<2.0", "1.5", "2.0"},
		{"pip", "example-package", "", "pkg:pypi/example-package", "vers:pypi/0.3.2.RC1", "0.3.2.RC1", "0.3.2"},
		{"pip", "example-package", "", "pkg:pypi/example-package", "vers:pypi/>=1.0RC1|!=1.0RC2|<1.0", "1.0RC1", "1.0RC2"},
		{"rubygems", "example-package", "", "pkg:gem/example-package", "vers:gem/>=1.0|<2.0", "1.5", "2.0"},
		{"nuget", "Example.Package", "", "pkg:nuget/Example.Package", "vers:nuget/>=1.0.0|<2.0.0", "1.5.0", "2.0.0"},
		{"go", "github.com/ExampleOrg/ExampleModule", "", "pkg:golang/github.com/ExampleOrg/ExampleModule", "vers:golang/>=1.0.0|<2.0.0", "1.5.0", "2.0.0"},
		{"cargo", "example-package", "", "pkg:cargo/example-package", "vers:cargo/>=1.0.0|<2.0.0", "1.5.0", "2.0.0"},
		{"npm", "example-package", "", "pkg:npm/example-package", "vers:npm/>=1.0.0|!=1.5.0|<2.0.0|>=3.0.0|<4.0.0", "3.1.0", "1.5.0"},
		{"npm", "example-package", "", "pkg:npm/example-package", "vers:npm/<1.0.0|>2.0.0", "2.1.0", "1.5.0"},
		{"pip", "example-package", "", "pkg:pypi/example-package", "vers:pypi/>=1.0|!=1.5|<2.0|>=3.0|<4.0", "3.1", "1.5"},
		{"debian", "example-package", "", "pkg:deb/debian/example-package?distro=bookworm", "vers:deb/<2.0-1", "1.5-1", "2.0-1"},
		{"debian", "example-package", "", "pkg:deb/debian/example-package?distro=bookworm", "vers:deb/*", "1.5-1", ""},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			m := fixtureMirror(t, true)
			db, e := mirror.Open(m, false)
			if e != nil {
				t.Fatal(e)
			}
			p := csaf.Product{Name: tc.ranges, ID: "synthetic"}
			p.Helper.PURL = tc.purl
			d := csaf.Document{}
			d.Document.CSAFVersion = "2.0"
			d.Document.Tracking.ID = "CVE-2026-1234"
			d.ProductTree.FullProductNames = []csaf.Product{p}
			d.Vulnerabilities = []csaf.Vulnerability{{CVE: "CVE-2026-1234", ProductStatus: map[string][]string{"known_affected": {"synthetic"}}}}
			raw, e := json.Marshal(d)
			if e != nil {
				t.Fatal(e)
			}
			compressed, e := mirror.Compress(raw)
			if e != nil {
				t.Fatal(e)
			}
			e = db.Update(func(tx *bolt.Tx) error {
				key := []byte("2026/cve-2026-1234.json")
				if e := tx.Bucket([]byte("documents")).Put(key, compressed); e != nil {
					return e
				}
				for _, b := range []string{"revisions", "inventory"} {
					if e := tx.Bucket([]byte(b)).Put(key, []byte("test")); e != nil {
						return e
					}
				}
				var s mirror.Snapshot
				if e := json.Unmarshal(tx.Bucket([]byte("metadata")).Get([]byte("snapshot")), &s); e != nil {
					return e
				}
				s.Indexed++
				s.Selected++
				s.Available++
				return putJSON(tx.Bucket([]byte("metadata")), "snapshot", s)
			})
			db.Close()
			if e != nil {
				t.Fatal(e)
			}
			out := filepath.Join(t.TempDir(), "cache")
			r, e := Build(context.Background(), Options{Mirror: m, Output: out, Validity: time.Hour})
			if e != nil {
				t.Fatal(e)
			}
			bucket := tc.typ + "::" + csaf.SourceName
			if tc.typ == "debian" {
				bucket = "debian 12"
			}
			if r.Buckets[bucket] == 0 {
				t.Fatalf("no %s bucket: %+v", tc.typ, r)
			}
			for _, ver := range []string{tc.affected, tc.safe} {
				if ver == "" {
					continue
				}
				base, query, hasQuery := strings.Cut(tc.purl, "?")
				purl := base + "@" + ver
				if hasQuery {
					purl += "?" + query
				}
				sbom := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []any{map[string]any{"type": "library", "name": tc.name, "group": tc.group, "version": ver, "purl": purl}}}
				path := filepath.Join(t.TempDir(), "sbom.json")
				if e = writeJSON(path, sbom); e != nil {
					t.Fatal(e)
				}
				cmd := exec.Command(trivy, "sbom", "--cache-dir", out, "--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update", "--offline-scan", "--skip-version-check", "--disable-telemetry", "--format", "json", path)
				if tc.typ == "debian" {
					cmd.Args = append(cmd.Args, "--distro", "debian/12")
				}
				var stderr strings.Builder
				cmd.Stderr = &stderr
				b, e := cmd.Output()
				if e != nil {
					t.Fatal(e, stderr.String())
				}
				found := strings.Contains(string(b), `"VulnerabilityID": "CVE-2026-1234"`)
				if found != (ver == tc.affected) {
					t.Fatalf("version %s: matched=%t\n%s\n%s", ver, found, b, stderr.String())
				}
				if strings.Contains(stderr.String(), "Version matching error") {
					t.Fatal(stderr.String())
				}
			}
		})
	}
}
