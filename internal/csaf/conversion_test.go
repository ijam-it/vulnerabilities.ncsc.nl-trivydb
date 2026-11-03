package csaf

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func conversionFixture(t *testing.T, cve, wantHash string) (Vulnerability, map[string]Product) {
	t.Helper()
	f, err := os.Open(filepath.Join("../../testdata/ncsc/conversion", "cve-"+cve[4:]+".json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	bytes, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	if hex.EncodeToString(sum[:]) != wantHash {
		t.Fatal("source fixture hash changed")
	}
	d, err := Decode(bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Vulnerabilities) != 1 || d.Vulnerabilities[0].CVE != cve {
		t.Fatal("unexpected fixture CVE")
	}
	return d.Vulnerabilities[0], d.Products()
}

func TestFrozenConversionExpectations(t *testing.T) {
	busy, products := conversionFixture(t, "CVE-2024-58251", "7d98aaac536e9e21c95ab91a9ca2b980f6e7a11eaad13b90aff30b03d5531b0e")
	entries, _, _ := Convert(busy, products)
	found := false
	for _, e := range entries {
		if e.Bucket == "alpine 3.20" && e.Package == "busybox" && e.Advisory.FixedVersion == "1.36.1-r31" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing Alpine busybox 3.20 fix boundary")
	}
	ssl, products := conversionFixture(t, "CVE-2024-12797", "7b01f3064403c03e76d7f423b2f89c76a4074b3a12b184bc895acaf000f0b706")
	entries, _, _ = Convert(ssl, products)
	found = false
	for _, e := range entries {
		if e.Bucket == "alpine 3.20" && e.Package == "openssl" && e.Advisory.FixedVersion == "3.3.3-r0" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing Alpine openssl source advisory")
	}
	debian, products := conversionFixture(t, "CVE-2022-0563", "bbe76d75a290e4d0c6b6b52e34d13fc76c611071d4b93cc57bc76218ec91b0b4")
	_, candidates, _ := Convert(debian, products)
	found = false
	for _, c := range candidates {
		if c.Bucket == "debian 12" && c.Package == "util-linux" && c.OriginalRange == "vers:deb/unknown" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing uncertain Debian util-linux candidate")
	}
	npm, products := conversionFixture(t, "CVE-2025-5889", "5023a96cce0b6a0293d9da3448583059a99f54841ea566235aec88bb76235ca9")
	entries, _, _ = Convert(npm, products)
	found = false
	for _, e := range entries {
		if e.Bucket != "npm::"+SourceName || e.Package != "brace-expansion" {
			continue
		}
		for _, rangeText := range e.Advisory.VulnerableVersions {
			if rangeText == "= 2.0.1" || rangeText == ">= 2.0.0, < 2.0.2" {
				t.Fatal("unsupported npm 2.0.1 inferred from other branch")
			}
			if rangeText == "= 3.0.0" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("explicit npm 3.0.0 observation missing")
	}
	musl, products := conversionFixture(t, "CVE-2025-26519", "daaa064457e34676443541c6b0322e364ce1887e45b3a27cd77ab74892d45bb8")
	entries, _, _ = Convert(musl, products)
	found = false
	for _, e := range entries {
		if e.Bucket == "alpine 3.20" && e.Package == "musl" && e.Advisory.FixedVersion == "1.2.5-r1" {
			found = true
		}
	}
	if !found {
		t.Fatal("holdout musl boundary missing")
	}
	sqlite, products := conversionFixture(t, "CVE-2025-29087", "4775b606b2dd4cab86d6192743bb5617fef28266722ba50f2866040b489879ba")
	entries, _, _ = Convert(sqlite, products)
	found = false
	for _, e := range entries {
		if e.Bucket == "alpine 3.20" && e.Package == "sqlite" && e.Advisory.FixedVersion == "3.45.3-r2" && e.Advisory.AffectedVersion == "3.44.0" {
			found = true
		}
	}
	if !found {
		t.Fatal("holdout sqlite lower and upper boundaries missing")
	}
}

func TestUnknownRangesAreCandidatesAcrossEcosystems(t *testing.T) {
	for _, tc := range []struct {
		name, purl, scheme, bucket string
	}{
		{"debian", "pkg:deb/debian/example?distro=bookworm", "deb", "debian 12"},
		{"ubuntu", "pkg:deb/ubuntu/example?distro=jammy", "deb", "ubuntu 22.04"},
		{"alpine", "pkg:apk/alpine/example?distro=3.20", "unknown", "alpine 3.20"},
		{"npm", "pkg:npm/example", "npm", "npm::" + SourceName},
		{"pip", "pkg:pypi/example", "pypi", "pip::" + SourceName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Product{ID: "p", Name: "vers:" + tc.scheme + "/unknown"}
			p.Helper.PURL = tc.purl
			v := Vulnerability{CVE: "CVE-2026-1234", ProductStatus: map[string][]string{"known_affected": {"p"}}}
			entries, candidates, unmapped := Convert(v, map[string]Product{"p": p})
			if len(entries) != 0 || len(candidates) != 1 || len(unmapped) != 0 {
				t.Fatalf("unexpected conversion: %v %v %v", entries, candidates, unmapped)
			}
			if c := candidates[0]; c.Bucket != tc.bucket || c.Package != "example" || c.Reason != "affected_versions_unspecified" || c.RuleID != "affected-versions-unspecified-v1" {
				t.Fatalf("incorrect candidate: %+v", c)
			}
		})
	}
}

func TestUnknownIsNotAnAllVersionAdvisory(t *testing.T) {
	p := Product{ID: "p", Name: "vers:deb/unknown"}
	p.Helper.PURL = "pkg:deb/debian/APT?distro=bookworm"
	v := Vulnerability{CVE: "CVE-2026-1234", ProductStatus: map[string][]string{"known_affected": {"p"}}}
	es, cs, us := Convert(v, map[string]Product{"p": p})
	if len(es) != 0 || len(cs) != 1 || len(us) != 0 || cs[0].Package != "apt" {
		t.Fatalf("unexpected result: %v %v %v", es, cs, us)
	}
	precise := Product{ID: "precise", Name: "vers:deb/<2.0-1"}
	precise.Helper.PURL = "pkg:deb/debian/apt?distro=bookworm"
	v.ProductStatus["known_affected"] = []string{"p", "precise"}
	es, cs, _ = Convert(v, map[string]Product{"p": p, "precise": precise})
	if len(cs) != 1 || len(es) != 1 || es[0].Advisory.FixedVersion != "2.0-1" || es[0].Advisory.Custom["NCSCOutcome"] != "supported" {
		t.Fatal("unknown range overrode precise fix", es, cs)
	}
	v.ProductStatus["known_affected"] = []string{"p"}
	p.Name = "vers:deb/<2.0-1"
	_, cs, us = Convert(v, map[string]Product{"p": p})
	if len(cs) != 0 || len(us) != 0 {
		t.Fatal("precise version was made uncertain")
	}
	p.Name = "vers:deb/>=1.0|<2.0"
	_, cs, us = Convert(v, map[string]Product{"p": p})
	if len(cs) != 0 || len(us) == 0 {
		t.Fatal("bounded Debian interval was broadened")
	}
}

func TestAlpineScopeAndOrdering(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		less bool
	}{{"1.0-r9", "1.0-r10", true}, {"1.0_rc1-r0", "1.0-r0", true}} {
		order, err := compareVersions("alpine", tc.a, tc.b)
		if err != nil || (order < 0) != tc.less {
			t.Fatalf("APK comparison %q %q: %d %v", tc.a, tc.b, order, err)
		}
	}
	p := Product{ID: "p", Vendor: "Alpine", Family: "Alpine:v3.20", PackageName: "busybox", Version: "vers:unknown/>=1.36.1-r20|<1.36.1-r31"}
	id, reason := Identify(p)
	if reason != "" || id.Release != "3.20" {
		t.Fatal(id, reason)
	}
	if r := osRelease("alpine", "alpine:v3.20.3"); r != "3.20" {
		t.Fatal("patch release was not normalized", r)
	}
	v := Vulnerability{CVE: "CVE-2026-1234", ProductStatus: map[string][]string{"known_affected": {"p"}}}
	es, _, _ := Convert(v, map[string]Product{"p": p})
	if len(es) != 1 || es[0].Advisory.AffectedVersion != "1.36.1-r20" || es[0].Advisory.FixedVersion != "1.36.1-r31" {
		t.Fatal(es)
	}
	p.Version = "vers:unknown/1.36.1-r29"
	es, _, us := Convert(v, map[string]Product{"p": p})
	if len(es) != 0 || len(us) != 1 {
		t.Fatal("exact APK version was broadened")
	}
	p.Version = "vers:unknown/>=1.36.1-r20|!=1.36.1-r29|<1.36.1-r31"
	es, _, us = Convert(v, map[string]Product{"p": p})
	if len(es) != 0 || len(us) != 1 || us[0].Reason != "os_affected_range_not_supported_by_stock_trivy" {
		t.Fatal("excluded point was broadened", es, us)
	}
	p.Helper.PURL = "pkg:apk/alpine/busybox?distro=3.20&arch=x86_64"
	if _, reason = Identify(p); reason != "os_architecture_scope_not_supported" {
		t.Fatal(reason)
	}
	p.Helper.PURL = "pkg:apk/alpine/busybox@1.36.1-r29?arch=source"
	id, reason = Identify(p)
	if reason != "" || id.Release != "3.20" || id.Version != "1.36.1-r29" {
		t.Fatal("source PURL lost tree release", id, reason)
	}
	p.PackageName = "other"
	if _, reason = Identify(p); reason != "os_package_identity_conflict" {
		t.Fatal("PURL/tree conflict not rejected", reason)
	}
	branch := Branch{Category: "architecture", Name: "arm64", Branches: []Branch{{Category: "product_version_range", Name: "vers:unknown/<1.36.1-r31", Product: &Product{ID: "arch"}}}}
	d := Document{}
	d.ProductTree.Branches = []Branch{branch}
	if _, reason = Identify(d.Products()["arch"]); reason != "os_scope_not_supported" {
		t.Fatal("architecture branch was broadened", reason)
	}
}
