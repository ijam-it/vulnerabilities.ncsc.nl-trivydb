package csaf

import (
	"strconv"
	"testing"
)

func TestAlpineRangeUnion(t *testing.T) {
	for _, tc := range []struct {
		name         string
		ranges       []string
		firstFixed   string
		lower, upper string
		conflict     bool
	}{
		{name: "xen nested ranges", ranges: []string{">=0|<4.13.4-r3", ">=0|<4.13.4-r2", ">=3.2|<4.13.4-r2"}, lower: "0", upper: "4.13.4-r3"},
		{name: "overlapping", ranges: []string{">=1|<3", ">=2|<4"}, lower: "1", upper: "4"},
		{name: "touching", ranges: []string{">=1|<2", ">=2|<3"}, lower: "1", upper: "3"},
		{name: "gap", ranges: []string{">=1|<2", ">=3|<4"}, conflict: true},
		{name: "bridge", ranges: []string{">=1|<2", ">=3|<4", ">=2|<3"}, lower: "1", upper: "4"},
		{name: "apk revision ordering", ranges: []string{">=1.0-r1|<1.0-r10", ">=1.0-r2|<1.0-r9"}, lower: "1.0-r1", upper: "1.0-r10"},
		{name: "unbounded overlap", ranges: []string{"<3", ">=2|<4"}, upper: "4"},
		{name: "unbounded gap", ranges: []string{"<2", ">=3|<4"}, conflict: true},
		{name: "all versions", ranges: []string{">=1|<2", ">=3|<4", "*"}},
		{name: "first fix confirms", ranges: []string{">=1|<3", ">=2|<4"}, firstFixed: "4", lower: "1", upper: "4"},
		{name: "first fix conflicts", ranges: []string{">=1|<3", ">=2|<4"}, firstFixed: "5", conflict: true},
		{name: "unbounded first fix", ranges: []string{"<3"}, firstFixed: "4", upper: "4"},
		{name: "first fix only", firstFixed: "4", upper: "4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			products := map[string]Product{}
			var ids []string
			for i, r := range tc.ranges {
				pid := strconv.Itoa(i)
				products[pid] = Product{ID: pid, Vendor: "Alpine", Family: "Alpine:v3.12", PackageName: "xen", Version: "vers:unknown/" + r}
				ids = append(ids, pid)
			}
			statuses := map[string][]string{}
			if tc.firstFixed != "" {
				products["fix"] = Product{ID: "fix", Vendor: "Alpine", Family: "Alpine:v3.12", PackageName: "xen", Version: "vers:unknown/" + tc.firstFixed}
				statuses["first_fixed"] = []string{"fix"}
			}
			// A bridge may occur after two disconnected observations. Check every
			// input order so an intermediate gap cannot make rejection permanent.
			var checkOrders func(int)
			checkOrders = func(i int) {
				if i < len(ids) {
					for j := i; j < len(ids); j++ {
						ids[i], ids[j] = ids[j], ids[i]
						checkOrders(i + 1)
						ids[i], ids[j] = ids[j], ids[i]
					}
					return
				}
				statuses["known_affected"] = ids
				es, candidates, excluded := Convert(Vulnerability{CVE: "CVE-2021-28706", ProductStatus: statuses}, products)
				if len(candidates) != 0 {
					t.Fatal("unexpected candidates", candidates)
				}
				if tc.conflict {
					if len(es) != 0 || len(excluded) != len(products) {
						t.Fatalf("order %v: expected all references excluded, got %v %v", ids, es, excluded)
					}
					for _, u := range excluded {
						if u.Reason != "os_affected_range_conflict" {
							t.Fatal(u.Reason)
						}
					}
					return
				}
				if len(es) != 1 || len(excluded) != 0 {
					t.Fatalf("order %v: expected one advisory, got %v %v", ids, es, excluded)
				}
				a := es[0].Advisory
				if es[0].Bucket != "alpine 3.12" || es[0].Package != "xen" || a.AffectedVersion != tc.lower || a.FixedVersion != tc.upper {
					t.Fatalf("order %v: got %+v; want [%s, %s)", ids, es[0], tc.lower, tc.upper)
				}
				if got := len(a.Custom["NCSCProductIDs"].([]string)); got != len(products) {
					t.Fatalf("lost product provenance: got %d, want %d", got, len(products))
				}
				if tc.upper == "" && (a.Status != 2 || a.Custom["NCSCAllVersionsAffected"] != true) {
					t.Fatal("lost all-version status", a)
				}
			}
			checkOrders(0)
		})
	}
}

func TestFrozenXenRangeUnion(t *testing.T) {
	v, products := conversionFixture(t, "CVE-2021-28706", "cc2a7353d1ef8e9754aa0c6292d0c36bcc0490970a4d681263f411f11182e1fa")
	es, _, excluded := Convert(v, products)
	for _, u := range excluded {
		if u.Reason == "os_affected_range_conflict" {
			t.Fatal("nested source ranges still excluded", u)
		}
	}
	for _, e := range es {
		if e.Bucket == "alpine 3.12" && e.Package == "xen" {
			if e.Advisory.AffectedVersion != "0" || e.Advisory.FixedVersion != "4.13.4-r3" || len(e.Advisory.Custom["NCSCProductIDs"].([]string)) != 3 {
				t.Fatal("incorrect xen union", e)
			}
			return
		}
	}
	t.Fatal("missing Alpine 3.12 xen advisory")
}
