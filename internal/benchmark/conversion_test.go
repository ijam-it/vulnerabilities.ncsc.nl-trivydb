package benchmark

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"ncsc-trivy-db/internal/build"
	"ncsc-trivy-db/internal/mirror"
)

func TestCompareConversionFindsLossesAndInputDrift(t *testing.T) {
	root := t.TempDir()
	snapshot := mirror.Snapshot{Source: mirror.Directory, Indexed: 1, Complete: true}
	write := func(name string, findings []Finding) (string, string) {
		cache := filepath.Join(root, name)
		if e := os.MkdirAll(filepath.Join(cache, "db"), 0755); e != nil {
			t.Fatal(e)
		}
		db, e := bolt.Open(filepath.Join(cache, "db", "trivy.db"), 0600, nil)
		if e != nil {
			t.Fatal(e)
		}
		db.Close()
		coverage := build.Report{Source: mirror.Directory, Snapshot: snapshot, DatabaseSHA256: name}
		data, e := json.Marshal(coverage)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(cache, "coverage.json"), data, 0644); e != nil {
			t.Fatal(e)
		}
		report := Report{StartedAt: time.Now(), SBOMSHA256: "same", TrivyVersion: "0.74.0", Databases: map[string]Database{"ncsc": {SHA256: name}, "trivy": {SHA256: "official"}}, Comparison: Comparison{NCSCOnly: findings}}
		data, e = json.Marshal(report)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(root, name+".json")
		if e = os.WriteFile(path, data, 0644); e != nil {
			t.Fatal(e)
		}
		return path, cache
	}
	old := Finding{Type: "alpine", Package: "busybox", Version: "1.0-r1", ID: "CVE-2026-1234", Severity: "HIGH", FixedVersion: "1.0-r2"}
	beforeReport, beforeCache := write("before", []Finding{old})
	afterReport, afterCache := write("after", nil)
	diff, e := CompareConversion(context.Background(), beforeReport, afterReport, beforeCache, afterCache)
	if e != nil || len(diff.Removed) != 1 || len(diff.Added) != 0 {
		t.Fatal(diff, e)
	}
	data, e := os.ReadFile(afterReport)
	if e != nil {
		t.Fatal(e)
	}
	var report Report
	if e = json.Unmarshal(data, &report); e != nil {
		t.Fatal(e)
	}
	report.SBOMSHA256 = "different"
	data, e = json.Marshal(report)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(afterReport, data, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = CompareConversion(context.Background(), beforeReport, afterReport, beforeCache, afterCache); e == nil {
		t.Fatal("different SBOM accepted")
	}
}
