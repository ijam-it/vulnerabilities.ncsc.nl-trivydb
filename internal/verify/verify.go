// Package verify validates a build's integrity and scans independent controls.
package verify

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ncsc-trivy-db/internal/build"
	"ncsc-trivy-db/internal/csaf"
	"ncsc-trivy-db/internal/scan"
)

type CaseResult struct {
	Case             string `json:"case"`
	CVE              string `json:"cve"`
	ExpectedAffected bool   `json:"expected_affected"`
	Detected         bool   `json:"detected"`
	Passed           bool   `json:"passed"`
}

type Report struct {
	VerifiedAt     time.Time    `json:"verified_at"`
	Complete       bool         `json:"complete"`
	Documents      int          `json:"documents"`
	DatabaseSHA256 string       `json:"database_sha256"`
	TrivyVersion   string       `json:"trivy_version"`
	Cases          []CaseResult `json:"cases"`
}

type control struct {
	label, name, group, version, purl, cve string
	affected                               bool
	distro                                 string
}

// Expectations come from the unmodified NCSC integration fixtures.
var controls = []control{
	{"maven-affected", "log4j-core", "org.apache.logging.log4j", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "CVE-2021-44228", true, ""},
	{"maven-fixed", "log4j-core", "org.apache.logging.log4j", "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", "CVE-2021-44228", false, ""},
	{"python-affected", "restrictedpython", "", "7.4", "pkg:pypi/restrictedpython@7.4", "CVE-2025-22153", true, ""},
	{"python-fixed", "restrictedpython", "", "8.0", "pkg:pypi/restrictedpython@8.0", "CVE-2025-22153", false, ""},
	{"debian-affected", "apache-log4j2", "", "2.14.1-1", "pkg:deb/debian/apache-log4j2@2.14.1-1?distro=bookworm", "CVE-2021-44228", true, "debian/12"},
	{"debian-fixed", "apache-log4j2", "", "2.15.0-1", "pkg:deb/debian/apache-log4j2@2.15.0-1?distro=bookworm", "CVE-2021-44228", false, "debian/12"},
	{"debian-other-release", "apache-log4j2", "", "2.14.1-1", "pkg:deb/debian/apache-log4j2@2.14.1-1?distro=bullseye", "CVE-2021-44228", false, "debian/11"},
	{"alpine-busybox-affected", "busybox", "", "1.36.1-r29", "pkg:apk/alpine/busybox@1.36.1-r29?distro=3.20.3", "CVE-2024-58251", true, "alpine/3.20"},
	{"alpine-busybox-fixed", "busybox", "", "1.36.1-r31", "pkg:apk/alpine/busybox@1.36.1-r31?distro=3.20.3", "CVE-2024-58251", false, "alpine/3.20"},
	{"alpine-busybox-other-release", "busybox", "", "1.36.1-r29", "pkg:apk/alpine/busybox@1.36.1-r29?distro=3.18.0", "CVE-2024-58251", false, "alpine/3.18"},
}

type runner func(context.Context, ...string) ([]byte, string, error)

// Check writes verification.json atomically only after all controls pass.
// Trivy scans use the supplied cache without downloading vulnerability data.
func Check(ctx context.Context, cache string, allowPartial bool, output io.Writer) (Report, error) {
	return check(ctx, cache, allowPartial, output, runTrivy)
}

func check(ctx context.Context, cache string, allowPartial bool, output io.Writer, run runner) (report Report, err error) {
	cache, err = filepath.Abs(cache)
	if err != nil {
		return report, err
	}
	var coverage build.Report
	if err = readJSON(filepath.Join(cache, "coverage.json"), &coverage); err != nil {
		return report, err
	}
	if !coverage.Complete && !allowPartial {
		return report, fmt.Errorf("refusing to verify a partial build as a full database")
	}
	if coverage.Complete && coverage.Documents != coverage.Snapshot.Indexed {
		return report, fmt.Errorf("document count does not match the full inventory")
	}
	for _, file := range []struct{ name, checksum string }{
		{"db/trivy.db", coverage.DatabaseSHA256}, {"db.tar.gz", coverage.ArchiveSHA256},
	} {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		sum, e := checksum(filepath.Join(cache, file.name))
		if e != nil {
			return report, e
		}
		if sum != file.checksum {
			return report, fmt.Errorf("checksum mismatch: %s", file.name)
		}
	}
	if err = checkArchive(filepath.Join(cache, "db.tar.gz")); err != nil {
		return report, err
	}
	var metadata build.Metadata
	if err = readJSON(filepath.Join(cache, "db", "metadata.json"), &metadata); err != nil {
		return report, err
	}
	if metadata.Version != 2 {
		return report, fmt.Errorf("unsupported schema version: %d", metadata.Version)
	}
	if coverage.PolicyVersion != "" {
		if coverage.PolicyVersion != csaf.PolicyVersion {
			return report, fmt.Errorf("unsupported conversion policy: %s", coverage.PolicyVersion)
		}
		db, e := bolt.Open(filepath.Join(cache, "db", "trivy.db"), 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
		if e != nil {
			return report, e
		}
		e = db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("ncsc-metadata"))
			if b == nil {
				return fmt.Errorf("missing NCSC metadata")
			}
			var stored struct {
				Version string `json:"version"`
			}
			if e := json.Unmarshal(b.Get([]byte("conversion-policy")), &stored); e != nil {
				return fmt.Errorf("conversion policy: %w", e)
			}
			if stored.Version != coverage.PolicyVersion {
				return fmt.Errorf("coverage policy differs from database")
			}
			candidates := tx.Bucket([]byte("ncsc-candidates"))
			if candidates == nil {
				return fmt.Errorf("missing candidate index")
			}
			count := 0
			if e := candidates.ForEach(func(k, v []byte) error {
				if v != nil {
					return fmt.Errorf("invalid candidate index")
				}
				count += candidates.Bucket(k).Stats().KeyN
				return nil
			}); e != nil {
				return e
			}
			if count != coverage.CandidateObservations {
				return fmt.Errorf("candidate count differs from coverage")
			}
			return nil
		})
		db.Close()
		if e != nil {
			return report, e
		}
	}
	destination := filepath.Join(cache, "verification-results")
	if err = os.MkdirAll(destination, 0755); err != nil {
		return report, err
	}
	temporary, err := os.MkdirTemp("", "ncsc-trivy-verify-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(temporary)
	for _, c := range controls {
		component := map[string]any{"type": "library", "name": c.name, "group": c.group, "version": c.version, "purl": c.purl}
		if strings.HasPrefix(c.distro, "alpine/") {
			component["properties"] = []map[string]string{{"name": "aquasecurity:trivy:PkgType", "value": "alpine"}, {"name": "aquasecurity:trivy:SrcName", "value": c.name}, {"name": "aquasecurity:trivy:SrcVersion", "value": c.version}}
		}
		sbom := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
			"components": []any{component}}
		file := filepath.Join(temporary, c.label+".cdx.json")
		if err = writeJSON(file, sbom); err != nil {
			return report, err
		}
		args, e := scan.Arguments("sbom", cache, []string{"--format", "json", file})
		if e != nil {
			return report, e
		}
		if c.distro != "" {
			args = append(args, "--distro", c.distro)
		}
		stdout, stderr, e := run(ctx, args...)
		if e != nil {
			return report, fmt.Errorf("%s: trivy: %w\n%s", c.label, e, stderr)
		}
		detected, e := checkFindings(stdout, stderr, c)
		if e != nil {
			return report, fmt.Errorf("%s: %w", c.label, e)
		}
		if err = os.WriteFile(filepath.Join(destination, c.label+".json"), stdout, 0644); err != nil {
			return report, err
		}
		report.Cases = append(report.Cases, CaseResult{c.label, c.cve, c.affected, detected, true})
		if output != nil {
			fmt.Fprintf(output, "PASS %s: %s detected=%t\n", c.label, c.cve, detected)
		}
	}
	version, stderr, err := run(ctx, "--version")
	if err != nil {
		return report, fmt.Errorf("trivy version: %w\n%s", err, stderr)
	}
	report.TrivyVersion = strings.TrimSpace(strings.SplitN(string(version), "\n", 2)[0])
	if report.TrivyVersion == "" {
		return report, fmt.Errorf("trivy returned an empty version")
	}
	report.VerifiedAt = time.Now().UTC()
	report.Complete = coverage.Complete
	report.Documents = coverage.Documents
	report.DatabaseSHA256 = coverage.DatabaseSHA256
	file, err := os.CreateTemp(cache, ".verification-*.json.tmp")
	if err != nil {
		return report, err
	}
	defer os.Remove(file.Name())
	if err = file.Close(); err != nil {
		return report, err
	}
	if err = writeJSON(file.Name(), report); err != nil {
		return report, err
	}
	path := filepath.Join(cache, "verification.json")
	if err = os.Rename(file.Name(), path); err != nil {
		return report, err
	}
	if output != nil {
		fmt.Fprintf(output, "Verified %d documents; results: %s\n", coverage.Documents, path)
	}
	return report, nil
}

func runTrivy(ctx context.Context, args ...string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "trivy", args...)
	cmd.WaitDelay = 5 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return stdout, stderr.String(), err
}

func checkFindings(stdout []byte, stderr string, c control) (bool, error) {
	var scan struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string
				DataSource      struct{ ID string }
			}
		}
	}
	if err := json.Unmarshal(stdout, &scan); err != nil {
		return false, fmt.Errorf("invalid Trivy JSON: %w", err)
	}
	detected := false
	for _, r := range scan.Results {
		for _, v := range r.Vulnerabilities {
			if v.DataSource.ID != csaf.SourceID {
				return false, fmt.Errorf("finding from a source other than NCSC")
			}
			if v.VulnerabilityID == c.cve {
				detected = true
			}
		}
	}
	if detected != c.affected {
		return detected, fmt.Errorf("expected %s present=%t, got %t", c.cve, c.affected, detected)
	}
	if strings.Contains(stderr, "Version matching error") {
		return detected, fmt.Errorf("Trivy could not interpret a constraint")
	}
	return detected, nil
}

func checksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func checkArchive(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	archive := tar.NewReader(gz)
	for _, name := range []string{"trivy.db", "metadata.json"} {
		h, err := archive.Next()
		if err != nil {
			return fmt.Errorf("archive entry %s: %w", name, err)
		}
		if h.Name != name || !h.FileInfo().Mode().IsRegular() {
			return fmt.Errorf("unexpected archive entry: %s", h.Name)
		}
	}
	if _, err = archive.Next(); err != io.EOF {
		return fmt.Errorf("unexpected archive entries or invalid archive: %v", err)
	}
	// Consume the gzip trailer so truncated or corrupt streams are rejected.
	_, err = io.Copy(io.Discard, gz)
	return err
}

func readJSON(path string, value any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, value); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
