package coverage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"ncsc-trivy-db/internal/build"
	"ncsc-trivy-db/internal/csaf"
	"ncsc-trivy-db/internal/mirror"
)

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "mirror.db")
	db, err := mirror.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	// Several CVEs in one document exercise provenance lookup rather than
	// assuming the CSAF filename always matches the requested CVE.
	raw := []byte(`{
	 "document":{"csaf_version":"2.0"},
	 "product_tree":{"branches":[{"category":"vendor","name":"Example","branches":[{"category":"product_name","name":"example","branches":[{"category":"product_version","name":"1.0.0","product":{"product_id":"npm","name":"example 1.0.0","product_identification_helper":{"purl":"pkg:npm/example@1.0.0"}}}]}]}],"full_product_names":[{"product_id":"cpe","name":"Example appliance","product_identification_helper":{"cpe":"cpe:2.3:a:example:appliance:*:*:*:*:*:*:*:*"}}]},
	 "vulnerabilities":[
	  {"cve":"CVE-2026-1000","product_status":{"known_affected":["npm"],"first_fixed":["npm"]}},
	  {"cve":"CVE-2026-1001","product_status":{"known_affected":["cpe","missing"]}},
	  {"cve":"CVE-2026-1002","product_status":{"fixed":["npm"]}},
	  {"cve":"CVE-2026-1003","product_status":{"known_affected":["npm","cpe"],"known_not_affected":["cpe"]}}
	 ]}`)
	compressed, err := mirror.Compress(raw)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"metadata", "documents", "inventory", "revisions"} {
			if _, err := tx.CreateBucket([]byte(name)); err != nil {
				return err
			}
		}
		key := []byte("2026/cve-2026-9999.json")
		for _, name := range []string{"inventory", "revisions"} {
			if err := tx.Bucket([]byte(name)).Put(key, []byte("rev")); err != nil {
				return err
			}
		}
		if err := tx.Bucket([]byte("documents")).Put(key, compressed); err != nil {
			return err
		}
		snapshot, err := json.Marshal(mirror.Snapshot{Indexed: 1, Selected: 1, Available: 1, Complete: true, StartedAt: time.Now().UTC()})
		if err != nil {
			return err
		}
		return tx.Bucket([]byte("metadata")).Put([]byte("snapshot"), snapshot)
	})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "cache")
	if _, err := build.Build(context.Background(), build.Options{Mirror: path, Output: cache, Validity: time.Hour}); err != nil {
		t.Fatal(err)
	}
	// A corrupt global export proves inspection never depends on reading it.
	if err := os.WriteFile(filepath.Join(cache, "unmapped-products.ndjson.gz"), []byte("unreadable"), 0600); err != nil {
		t.Fatal(err)
	}
	return cache
}

func TestCoverageInventoryAndUncoveredProducts(t *testing.T) {
	r, err := Open(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx := context.Background()
	s, err := r.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.CVEs != 4 || s.WithMatches != 2 || s.WithoutMatches != 2 || s.Advisories != 2 || !s.SourceComplete || !s.ReasonsAvailable || s.ExcludedProducts != 3 {
		t.Fatalf("bad summary: %+v", s)
	}
	d, err := r.Detail(ctx, "CVE-2026-1003")
	if err != nil {
		t.Fatal(err)
	}
	if d.Matched != 1 || d.Excluded != 1 || d.Ignored != 1 || d.Advisories != 1 || len(d.Products) != 1 {
		t.Fatalf("bad detail: %+v", d)
	}
	if d.Products[0].Reason != "cpe_without_package_identity" {
		t.Fatalf("lost source context: %+v", d.Products)
	}
	fixed, err := r.Detail(ctx, "CVE-2026-1000")
	if err != nil || fixed.Matched != 1 || fixed.Ignored != 1 || len(fixed.Products) != 0 {
		t.Fatalf("first_fixed language observation misclassified: %+v, %v", fixed, err)
	}
	missing, err := r.Detail(ctx, "CVE-2026-1001")
	if err != nil || missing.Reasons["missing_product_reference"] != 1 || len(missing.Products) != 2 {
		t.Fatalf("missing reference not explained: %+v, %v", missing, err)
	}
	if _, err := r.Detail(ctx, "CVE-2026-9998"); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("absent CVE: %v", err)
	}
	page, err := r.List(ctx, "", 1)
	if err != nil || len(page.Rows) != 1 || page.Rows[0].CVE != "CVE-2026-1001" || page.NextAfter != page.Rows[0].CVE {
		t.Fatalf("bad first list page: %+v, %v", page, err)
	}
	page, err = r.List(ctx, page.NextAfter, 1)
	if err != nil || len(page.Rows) != 1 || page.Rows[0].CVE != "CVE-2026-1002" || page.Rows[0].Ignored != 1 || page.NextAfter != "" {
		t.Fatalf("bad last list page: %+v, %v", page, err)
	}
	page, err = r.List(ctx, "CVE-2026-9999", 20)
	if err != nil || len(page.Rows) != 0 || page.NextAfter != "" {
		t.Fatalf("bad past-end cursor: %+v, %v", page, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := r.List(ctx, "", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
}

func TestMissingStoredAdvisory(t *testing.T) {
	cache := fixture(t)
	db, err := mirror.Open(filepath.Join(cache, "db", "trivy.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("npm::" + csaf.SourceName)).Bucket([]byte("example")).Delete([]byte("CVE-2026-1003"))
	})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Open(cache)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	d, err := r.Detail(context.Background(), "CVE-2026-1003")
	if err != nil || d.Matched != 0 || d.Reasons["missing_database_advisory"] != 1 {
		t.Fatalf("missing stored advisory claimed as matched: %+v, %v", d, err)
	}
	if _, err := r.Summary(context.Background()); err == nil || !strings.Contains(err.Error(), "does not describe") {
		t.Fatalf("stale sidecar accepted: %v", err)
	}
}

func TestSummaryWithoutSidecarAndValidation(t *testing.T) {
	cache := fixture(t)
	if err := os.Rename(filepath.Join(cache, "coverage.json"), filepath.Join(cache, "saved-coverage.json")); err != nil {
		t.Fatal(err)
	}
	r, err := Open(cache)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s, err := r.Summary(context.Background())
	if err != nil || s.ReasonsAvailable || s.CVEs != 4 || s.WithoutMatches != 2 {
		t.Fatalf("sidecar required: %+v, %v", s, err)
	}
	if id, err := CVE("cve-2026-1000"); err != nil || id != "CVE-2026-1000" {
		t.Fatal(id, err)
	}
	if _, err := CVE("../2026/cve-2026-1000.json"); err == nil {
		t.Fatal("invalid CVE accepted")
	}
}

func TestLegacyBuildPolicyIsExplicitlyUnavailable(t *testing.T) {
	cache := fixture(t)
	db, e := mirror.Open(filepath.Join(cache, "db", "trivy.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	e = db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("ncsc-metadata")).Delete([]byte("conversion-policy")) })
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	r, e := Open(cache)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	d, e := r.Detail(context.Background(), "CVE-2026-1000")
	if e != nil || d.PolicyAvailable || !strings.Contains(d.PolicyVersion, "unavailable") {
		t.Fatalf("legacy policy silently inferred: %+v %v", d, e)
	}
}
