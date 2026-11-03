package verify

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	bolt "go.etcd.io/bbolt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ncsc-trivy-db/internal/build"
	"ncsc-trivy-db/internal/csaf"
	"ncsc-trivy-db/internal/mirror"
)

func TestRecordedPolicyAndCandidateCountAreVerified(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*build.Report)
	}{{"policy", func(r *build.Report) { r.PolicyVersion = "unsupported" }}, {"candidates", func(r *build.Report) { r.CandidateObservations = 1 }}} {
		t.Run(tc.name, func(t *testing.T) {
			cache, coverage := fixture(t)
			path := filepath.Join(cache, "db", "trivy.db")
			if e := os.Truncate(path, 0); e != nil {
				t.Fatal(e)
			}
			db, e := bolt.Open(path, 0600, nil)
			if e != nil {
				t.Fatal(e)
			}
			e = db.Update(func(tx *bolt.Tx) error {
				meta, e := tx.CreateBucket([]byte("ncsc-metadata"))
				if e != nil {
					return e
				}
				if _, e = tx.CreateBucket([]byte("ncsc-candidates")); e != nil {
					return e
				}
				data, e := json.Marshal(struct {
					Version string `json:"version"`
				}{csaf.PolicyVersion})
				if e != nil {
					return e
				}
				return meta.Put([]byte("conversion-policy"), data)
			})
			db.Close()
			if e != nil {
				t.Fatal(e)
			}
			coverage.PolicyVersion = csaf.PolicyVersion
			tc.mutate(&coverage)
			saveCoverage(t, cache, &coverage)
			_, e = check(context.Background(), cache, false, nil, func(context.Context, ...string) ([]byte, string, error) {
				t.Fatal("Trivy ran after policy integrity failure")
				return nil, "", nil
			})
			if e == nil {
				t.Fatal("tampered policy or candidate count passed verification")
			}
		})
	}
}

func fixture(t *testing.T) (string, build.Report) {
	t.Helper()
	cache := t.TempDir()
	if err := os.Mkdir(filepath.Join(cache, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "db", "trivy.db"), []byte("fixture database"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(cache, "db", "metadata.json"), build.Metadata{Version: 2}); err != nil {
		t.Fatal(err)
	}
	writeArchive(t, cache, "trivy.db", "metadata.json")
	coverage := build.Report{Complete: true, Documents: 6, Snapshot: mirror.Snapshot{Indexed: 6}}
	saveCoverage(t, cache, &coverage)
	return cache, coverage
}

func writeArchive(t *testing.T, cache string, names ...string) {
	t.Helper()
	f, err := os.Create(filepath.Join(cache, "db.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		b := []byte("fixture " + name)
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(b)), Mode: 0644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	for _, closer := range []io.Closer{tw, gz, f} {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func saveCoverage(t *testing.T, cache string, coverage *build.Report) {
	t.Helper()
	var err error
	coverage.DatabaseSHA256, err = checksum(filepath.Join(cache, "db", "trivy.db"))
	if err != nil {
		t.Fatal(err)
	}
	coverage.ArchiveSHA256, err = checksum(filepath.Join(cache, "db.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(cache, "coverage.json"), coverage); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrityFailures(t *testing.T) {
	for _, name := range []string{"partial", "count", "database-checksum", "archive-checksum", "archive-extra", "archive-missing", "schema"} {
		t.Run(name, func(t *testing.T) {
			cache, coverage := fixture(t)
			want := ""
			switch name {
			case "partial":
				coverage.Complete = false
				want = "partial build"
			case "count":
				coverage.Documents--
				want = "document count"
			case "database-checksum":
				coverage.DatabaseSHA256 = "invalid"
				want = "checksum mismatch: db/trivy.db"
			case "archive-checksum":
				coverage.ArchiveSHA256 = "invalid"
				want = "checksum mismatch: db.tar.gz"
			case "archive-extra":
				writeArchive(t, cache, "trivy.db", "metadata.json", "unexpected")
				saveCoverage(t, cache, &coverage)
				want = "unexpected archive entries"
			case "archive-missing":
				writeArchive(t, cache, "trivy.db")
				saveCoverage(t, cache, &coverage)
				want = "archive entry metadata.json"
			case "schema":
				if err := writeJSON(filepath.Join(cache, "db", "metadata.json"), build.Metadata{Version: 3}); err != nil {
					t.Fatal(err)
				}
				want = "unsupported schema version"
			}
			if err := writeJSON(filepath.Join(cache, "coverage.json"), coverage); err != nil {
				t.Fatal(err)
			}
			_, err := check(context.Background(), cache, false, nil, func(context.Context, ...string) ([]byte, string, error) {
				t.Fatal("Trivy ran before integrity checks passed")
				return nil, "", nil
			})
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want %q", err, want)
			}
			if _, err := os.Stat(filepath.Join(cache, "verification.json")); !os.IsNotExist(err) {
				t.Fatal("failed verification published a report")
			}
		})
	}
}

func TestCheckPublishesReport(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "partial"}[partial], func(t *testing.T) {
			cache, coverage := fixture(t)
			coverage.Complete = !partial
			saveCoverage(t, cache, &coverage)
			var labels []string
			report, err := check(context.Background(), cache, partial, io.Discard, func(ctx context.Context, args ...string) ([]byte, string, error) {
				if slices.Equal(args, []string{"--version"}) {
					return []byte("Version: 0.74.0\nOther information\n"), "", nil
				}
				for _, flag := range []string{"--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update", "--offline-scan", "--skip-version-check", "--disable-telemetry"} {
					if !slices.Contains(args, flag) {
						t.Fatalf("missing offline flag %s", flag)
					}
				}
				var file string
				for _, arg := range args {
					if strings.HasSuffix(arg, ".cdx.json") {
						file = arg
					}
				}
				var sbom struct{ Components []struct{ Name, PURL string } }
				if err := readJSON(file, &sbom); err != nil || len(sbom.Components) != 1 || sbom.Components[0].PURL == "" {
					t.Fatalf("invalid SBOM: %+v, %v", sbom, err)
				}
				label := strings.TrimSuffix(filepath.Base(file), ".cdx.json")
				labels = append(labels, label)
				if strings.HasPrefix(label, "debian-") || strings.HasPrefix(label, "alpine-") {
					distro := "debian/12"
					if label == "debian-other-release" {
						distro = "debian/11"
					}
					if strings.HasPrefix(label, "alpine-") {
						distro = "alpine/3.20"
						if label == "alpine-busybox-other-release" {
							distro = "alpine/3.18"
						}
					}
					if !slices.Equal(args[len(args)-2:], []string{"--distro", distro}) {
						t.Fatalf("wrong distro arguments: %v", args)
					}
				}
				if strings.HasSuffix(label, "-affected") {
					cve := "CVE-2021-44228"
					if label == "python-affected" {
						cve = "CVE-2025-22153"
					}
					if label == "alpine-busybox-affected" {
						cve = "CVE-2024-58251"
					}
					return []byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"` + cve + `","DataSource":{"ID":"ncsc-nl"}}]}]}`), "", nil
				}
				return []byte(`{"Results":[]}`), "", nil
			})
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"maven-affected", "maven-fixed", "python-affected", "python-fixed", "debian-affected", "debian-fixed", "debian-other-release", "alpine-busybox-affected", "alpine-busybox-fixed", "alpine-busybox-other-release"}
			if !slices.Equal(labels, want) || report.Complete != !partial || report.Documents != 6 || report.TrivyVersion != "Version: 0.74.0" {
				t.Fatalf("unexpected controls or report: %v, %+v", labels, report)
			}
			var saved Report
			if err := readJSON(filepath.Join(cache, "verification.json"), &saved); err != nil || len(saved.Cases) != len(want) || saved.VerifiedAt.IsZero() {
				t.Fatalf("invalid published report: %+v, %v", saved, err)
			}
			for _, label := range labels {
				if _, err := os.Stat(filepath.Join(cache, "verification-results", label+".json")); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestScanFailuresPreserveReport(t *testing.T) {
	for _, tc := range []struct {
		name, stdout, stderr string
		err                  error
	}{
		{"missing-finding", `{"Results":[]}`, "", nil},
		{"foreign-source", `{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2021-44228","DataSource":{"ID":"nvd"}}]}]}`, "", nil},
		{"invalid-json", `invalid`, "", nil},
		{"invalid-constraint", `{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2021-44228","DataSource":{"ID":"ncsc-nl"}}]}]}`, "Version matching error", nil},
		{"process-failure", "", "scan failed", errors.New("exit status 1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, _ := fixture(t)
			path := filepath.Join(cache, "verification.json")
			if err := os.WriteFile(path, []byte("previous report"), 0644); err != nil {
				t.Fatal(err)
			}
			_, err := check(context.Background(), cache, false, nil, func(context.Context, ...string) ([]byte, string, error) {
				return []byte(tc.stdout), tc.stderr, tc.err
			})
			if err == nil {
				t.Fatal("accepted failed scan")
			}
			b, err := os.ReadFile(path)
			if err != nil || string(b) != "previous report" {
				t.Fatal("failed scan replaced previous report", err)
			}
		})
	}
}

func TestCancellation(t *testing.T) {
	cache, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Check(ctx, cache, false, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
