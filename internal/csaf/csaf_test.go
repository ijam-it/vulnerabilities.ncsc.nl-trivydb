package csaf

import (
	"reflect"
	"testing"
)

func TestConstraints(t *testing.T) {
	for _, tc := range []struct {
		value  string
		want   []string
		reason string
	}{
		{"vers:npm/>=1.2.0|<2.0.0", []string{">= 1.2.0, < 2.0.0"}, ""},
		{"vers:unknown/1.0|1.5", []string{"= 1.0", "= 1.5"}, ""},
		{"vers:unknown/<v2.7.0", []string{"< 2.7.0"}, ""},
		{"vers:unknown/unknown", nil, "affected_versions_unspecified"},
		{"vers:unknown/>=1.0|<2.0|>=3.0|<4.0", []string{">= 1.0, < 2.0", ">= 3.0, < 4.0"}, ""},
		{"vers:unknown/<3.0 only with feature enabled", nil, "unsupported_version_range"},
		{"vers:unknown/>=1.0|!=1.2|<2.0", []string{">= 1.0, < 1.2", "> 1.2, < 2.0"}, ""},
		{"vers:unknown/<1.0|>2.0", []string{"< 1.0", "> 2.0"}, ""},
		{"vers:unknown/>=2.0|<1.0", nil, "invalid_version_range_order"},
		{"vers:unknown/!=1.0|!=2.0", []string{"< 1.0", "> 1.0, < 2.0", "> 2.0"}, ""},
		{"vers:unknown/0.5|>=1.0|<2.0|3.0", []string{"= 0.5", "= 3.0", ">= 1.0, < 2.0"}, ""},
		{"vers:unknown/>=1.0|>=2.0", nil, "invalid_version_range_sequence"},
		{"vers:unknown/1.0|<2.0", nil, "invalid_version_range_sequence"},
		{"vers:unknown/1.0|1.0", nil, "invalid_version_range_order"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			got, reason := Constraints(Product{Version: tc.value}, Identity{})
			if !reflect.DeepEqual(got, Unique(tc.want)) || reason != tc.reason {
				t.Fatalf("got %v (%s), want %v (%s)", got, reason, tc.want, tc.reason)
			}
		})
	}
}

func TestIdentityAndStatus(t *testing.T) {
	p := Product{ID: "p", Version: "vers:unknown/1.0"}
	p.Helper.PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	id, reason := Identify(p)
	if reason != "" || id.Package != "org.apache.logging.log4j:log4j-core" || id.Ecosystem != "maven" {
		t.Fatal(id, reason)
	}
	c, r := Constraints(p, id)
	if r != "" || !reflect.DeepEqual(c, []string{"= 2.14.1"}) {
		t.Fatal(c, r)
	}
	for _, status := range []string{"fixed", "known_not_affected", "under_investigation", "recommended", "last_affected"} {
		es, _ := Entries(Vulnerability{CVE: "CVE-2026-1234", ProductStatus: map[string][]string{status: {"p"}}}, map[string]Product{"p": p})
		if len(es) != 0 {
			t.Fatalf("%s must not become an affected advisory", status)
		}
	}
	p.Helper.PURL = ""
	p.Helper.CPE = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
	if _, reason = Identify(p); reason != "cpe_without_package_identity" {
		t.Fatal(reason)
	}
}

func TestQualifiedAndDistroIdentities(t *testing.T) {
	p := Product{}
	p.Helper.PURL = "pkg:deb/debian/openssl@3.0.1?distro=bookworm"
	id, reason := Identify(p)
	if reason != "" || id.Release != "12" || id.Package != "openssl" {
		t.Fatal(id, reason)
	}
	p.Helper.PURL = "pkg:deb/debian/openssl@3.0.1"
	if _, reason = Identify(p); reason != "os_purl_without_distro" {
		t.Fatal(reason)
	}
	p.Helper.PURL = "pkg:npm/foo@1.0.0?os=windows"
	if _, reason = Identify(p); reason != "qualified_language_purl" {
		t.Fatal(reason)
	}
	p.Helper.PURL = "pkg:golang/github.com/SomeOrg/SomeModule@v1.0.0"
	id, reason = Identify(p)
	if reason != "" || id.Package != "github.com/SomeOrg/SomeModule" {
		t.Fatal(id, reason)
	}
}
