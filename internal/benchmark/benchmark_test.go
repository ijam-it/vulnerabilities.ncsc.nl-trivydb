package benchmark

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Match identities must distinguish package versions/ecosystems, but deduplicate
// repeated installations of the same package/version/CVE for the headline counts.
func TestComparison(t *testing.T) {
	makeReport := func(source, severity, fixed string) scanReport {
		raw := fmt.Sprintf(`{"SchemaVersion":2,"Results":[{"Type":"npm","Packages":[{"Name":"example","Version":"1"}],"Vulnerabilities":[
		{"PkgName":"example","InstalledVersion":"1","VulnerabilityID":"CVE-1","Severity":%q,"FixedVersion":%q,"DataSource":{"ID":%q}},
		{"PkgName":"example","InstalledVersion":"1","VulnerabilityID":"CVE-1","Severity":%q,"FixedVersion":%q,"DataSource":{"ID":%q}},
		{"PkgName":"example","InstalledVersion":"2","VulnerabilityID":"CVE-1","DataSource":{"ID":%q}}
		]}]}`, severity, fixed, source, severity, fixed, source, source)
		r, err := decode([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	n, tr := makeReport("ncsc-nl", "HIGH", "3"), makeReport("ghsa", "LOW", "4")
	tr.Results[0].Vulnerabilities[2].VulnerabilityID = "CVE-2"
	c := compare(n, tr)
	if c.NCSC.Findings != 2 || c.NCSC.UniqueIDs != 1 || c.Trivy.UniqueIDs != 2 || len(c.Shared) != 1 || len(c.NCSCOnly) != 1 || len(c.TrivyOnly) != 1 {
		t.Fatalf("bad comparison: %+v", c)
	}
	if len(c.MetadataDifferences) != 1 || c.MetadataDifferences[0].NCSC.FixedVersion != "3" || c.MetadataDifferences[0].Trivy.Severity != "LOW" {
		t.Fatalf("missing metadata difference: %+v", c)
	}
	if c.NCSC.BySeverity["UNKNOWN"] != 1 {
		t.Fatal("missing severities must count as UNKNOWN")
	}
}

func TestImageParity(t *testing.T) {
	read := func(raw string) scanReport {
		r, err := decode([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	sbom := read(`{"SchemaVersion":2,"Results":[{"Type":"debian","Packages":[{"Name":"bash","Version":"5.2.15-2+b7","Identifier":{"PURL":"pkg:deb/debian/bash@5.2.15-2%2Bb7"}}]}]}`)
	image := read(`{"SchemaVersion":2,"Results":[{"Type":"debian","Packages":[{"Name":"bash","Version":"5.2.15","Identifier":{"PURL":"pkg:deb/debian/bash@5.2.15-2%2Bb7"}}]}]}`)
	if err := validateParity(sbom, image); err != nil {
		t.Fatalf("Debian version representation should normalize through PURL: %v", err)
	}
	image.Results[0].Packages[0].Identifier.PURL = "pkg:deb/debian/bash@5.2.15-2%2Bb8"
	if err := validateParity(sbom, image); err == nil {
		t.Fatal("changed Debian revision went undetected")
	}
	image = sbom
	image.Results[0].Type = "alpine"
	if err := validateParity(read(`{"SchemaVersion":2,"Results":[{"Type":"debian","Packages":[{"Name":"bash","Version":"1"}]}]}`), image); err == nil {
		t.Fatal("ecosystem change went undetected")
	}
	if _, err := decode([]byte(`{"SchemaVersion":2,"Results":[]}`)); err != nil {
		t.Fatal("schema-valid scan with no recognized packages should decode for vendor SBOMs")
	}
}

func TestSummarizeSBOM(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","components":[{"type":"library","purl":"pkg:golang/example@1","cpe":"cpe:2.3:a:example:example:1:*:*:*:*:*:*:*"},{"type":"firmware","cpe":"cpe:2.3:o:example:firmware:1:*:*:*:*:*:*:*"}]}`)
	s := summarizeSBOM(raw)
	if s.Format != "CycloneDX" || s.Components != 2 || s.ByType["firmware"] != 1 || s.WithPURL != 1 || s.WithCPE != 2 || s.CPEOnly != 1 {
		t.Fatalf("wrong SBOM inventory: %+v", s)
	}
}

func TestSBOMCommand(t *testing.T) {
	root := t.TempDir()
	cache := func(name string) string {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Join(path, "db"), 0755); err != nil {
			t.Fatal(err)
		}
		raw := []byte(name)
		sum := sha256.Sum256(raw)
		for file, content := range map[string][]byte{"db/trivy.db": raw, "db/metadata.json": []byte(`{"Version":2}`), "coverage.json": []byte(fmt.Sprintf(`{"complete":true,"database_sha256":%q}`, hex.EncodeToString(sum[:])))} {
			if err := os.WriteFile(filepath.Join(path, file), content, 0644); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	ncsc, official := cache("ncsc"), cache("official")
	// Fake only the external process boundary; exercise flags, snapshots, raw
	// evidence, source isolation, and command output through the real Run path.
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo 'Version: test'; exit 0; fi
case "$*" in *--skip-db-update*--offline-scan*) ;; *) exit 9 ;; esac
case "$*" in *--cache-dir*ncsc*) source=ncsc-nl ;; *) source=ghsa ;; esac
printf '{"SchemaVersion":2,"Results":[{"Type":"npm","Packages":[{"Name":"example","Version":"1"}],"Vulnerabilities":[{"PkgName":"example","InstalledVersion":"1","VulnerabilityID":"CVE-1","DataSource":{"ID":"%s"}}]}]}' "$source"
`
	if err := os.WriteFile(filepath.Join(root, "trivy"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	input := filepath.Join(root, "input.json")
	if err := os.WriteFile(input, []byte(`{"bomFormat":"CycloneDX"}`), 0644); err != nil {
		t.Fatal(err)
	}
	o := Options{Kind: "sbom", Target: input, NCSCCache: ncsc, TrivyCache: official, Output: filepath.Join(root, "result"), Timeout: 10 * time.Second}
	var output bytes.Buffer
	r, err := Run(context.Background(), o, &output)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Comparison.Shared) != 1 || r.Validation["ncsc"].ImageParity != nil || !strings.Contains(output.String(), "original image not checked") {
		t.Fatalf("unexpected result: %+v\n%s", r, &output)
	}
	for _, file := range []string{"report.json", "differences.txt", "sbom.json", "ncsc-sbom.json.gz", "trivy-sbom.json.gz", "ncsc-sbom.log"} {
		if _, err := os.Stat(filepath.Join(o.Output, file)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Run(context.Background(), o, &output); err == nil {
		t.Fatal("overwrote existing evidence directory")
	}
	o.Output = filepath.Join(root, "same-db")
	o.TrivyCache = o.NCSCCache
	if _, err := Run(context.Background(), o, &output); err == nil {
		t.Fatal("accepted same database for both sides")
	}

	// A real vendor SBOM can contain components that stock Trivy cannot scan.
	if err := os.WriteFile(input, []byte(`{"bomFormat":"CycloneDX","components":[{"type":"firmware","purl":"pkg:generic/device@1","cpe":"cpe:2.3:o:example:device:1:*:*:*:*:*:*:*"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "trivy"), []byte("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'Version: test'; else echo '{\"SchemaVersion\":2,\"Results\":[]}'; fi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	o.Output = filepath.Join(root, "no-recognized-packages")
	o.TrivyCache = official
	output.Reset()
	r, err = Run(context.Background(), o, &output)
	if err != nil || r.SBOM.Components != 1 || r.Validation["trivy"].Packages != 0 || !strings.Contains(output.String(), "No SBOM packages were recognized") {
		t.Fatalf("expected an explicit unscanned-inventory result, got %+v, %v, %s", r, err, &output)
	}
}
