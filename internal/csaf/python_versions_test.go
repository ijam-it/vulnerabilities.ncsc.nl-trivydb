package csaf

import (
	"reflect"
	"testing"

	pep440 "github.com/aquasecurity/go-pep440-version"
)

func TestPythonConstraintCaseNormalization(t *testing.T) {
	for _, tc := range []struct {
		name, purl, version, reason string
		want                        []string
		matches                     map[string]bool
	}{
		{
			name: "exact PURL takes precedence", purl: "pkg:pypi/gitpython@0.3.2.RC1", version: "vers:unknown/<3.1.30",
			want:    []string{"== 0.3.2.rc1"},
			matches: map[string]bool{"0.3.2.RC1": true, "0.3.2rc1": true, "0.3.2rc2": false, "0.3.2": false, "3.1.30": false},
		},
		{
			name: "range keeps bounds and exclusion", purl: "pkg:pypi/example", version: "vers:pypi/>=1.0RC1|!=1.0RC2|<1.0",
			want:    []string{">= 1.0rc1, < 1.0rc2", "> 1.0rc2, < 1.0"},
			matches: map[string]bool{"1.0b1": false, "1.0RC1": true, "1.0RC2": false, "1.0rc3": true, "1.0": false},
		},
		{name: "git tag stays excluded", purl: "pkg:pypi/nltk@2.0.1rc2-git", reason: "trivy_cannot_parse_version_constraint"},
		{name: "Composer stays excluded", purl: "pkg:composer/funadmin/funadmin@v7.0.0_rc1", reason: "trivy_cannot_parse_version_constraint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Product{ID: "p", Version: tc.version}
			p.Helper.PURL = tc.purl
			v := Vulnerability{CVE: "CVE-2026-1234", ProductStatus: map[string][]string{"known_affected": {"p"}}}
			entries, candidates, excluded := Convert(v, map[string]Product{"p": p})
			if len(candidates) != 0 {
				t.Fatal("unexpected candidates", candidates)
			}
			if tc.reason != "" {
				if len(entries) != 0 || len(excluded) != 1 || excluded[0].Reason != tc.reason {
					t.Fatalf("unexpected result: %v %v", entries, excluded)
				}
				return
			}
			if len(entries) != 1 || len(excluded) != 0 || !reflect.DeepEqual(entries[0].Advisory.VulnerableVersions, Unique(tc.want)) {
				t.Fatalf("unexpected result: %v %v", entries, excluded)
			}
			for raw, want := range tc.matches {
				version, err := pep440.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				matched := false
				for _, constraint := range entries[0].Advisory.VulnerableVersions {
					parsed, err := pep440.NewSpecifiers(constraint, pep440.WithPreRelease(true))
					if err != nil {
						t.Fatal(err)
					}
					matched = matched || parsed.Check(version)
				}
				if matched != want {
					t.Errorf("version %s: matched=%t, want %t", raw, matched, want)
				}
			}
		})
	}
}

func TestFrozenGitPythonVersionCase(t *testing.T) {
	v, products := conversionFixture(t, "CVE-2022-24439", "ab3d491323284e807e2eadcf3b679d1df872471aa8aae7bef2d71f8df1340801")
	const pid = "CSAFPID-6614810"
	// Isolate the previously excluded reference so another range cannot hide it.
	v.ProductStatus = map[string][]string{"known_affected": {pid}}
	entries, candidates, excluded := Convert(v, products)
	if len(entries) != 1 || len(candidates) != 0 || len(excluded) != 0 {
		t.Fatalf("unexpected result: %v %v %v", entries, candidates, excluded)
	}
	e := entries[0]
	if e.Bucket != "pip::"+SourceName || e.Package != "gitpython" || !reflect.DeepEqual(e.Advisory.VulnerableVersions, []string{"== 0.3.2.rc1"}) {
		t.Fatal("incorrect GitPython rule", e)
	}
	observations := e.Advisory.Custom["NCSCObservations"].([]map[string]string)
	if len(observations) != 1 || observations[0]["product_id"] != pid || observations[0]["range"] != "vers:unknown/0.3.2.rc1" {
		t.Fatal("lost original observation", observations)
	}
	if products[pid].Helper.PURL != "pkg:pypi/gitpython@0.3.2.RC1" {
		t.Fatal("source PURL was changed")
	}
}
