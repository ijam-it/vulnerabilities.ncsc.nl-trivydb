package scan

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestArgumentsProtectNCSCDatabase(t *testing.T) {
	for _, flag := range append([]string{"--cache-dir", "--scanners"}, managedFlags...) {
		for _, arg := range []string{flag, flag + "=false"} {
			if _, err := Arguments("sbom", "cache", []string{"target.json", arg}); err == nil {
				t.Errorf("accepted override %s", arg)
			}
		}
	}
	args, err := Arguments("sbom", "cache with spaces", []string{"--format", "json", "--", "--offline-scan=false"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(args[:3], []string{"sbom", "--cache-dir", "cache with spaces"}) ||
		!slices.Equal(args[len(args)-4:], []string{"--format", "json", "--", "--offline-scan=false"}) {
		t.Fatalf("arguments or delimiter changed: %v", args)
	}
	for _, flag := range managedFlags {
		if !slices.Contains(args, flag) {
			t.Errorf("missing managed flag %s", flag)
		}
	}
	if _, err := Arguments("unknown", "cache", nil); err == nil {
		t.Fatal("accepted unsupported command")
	}
}

func TestRunRejectsMissingOrInvalidDatabase(t *testing.T) {
	for _, name := range []string{"trivy.db", "metadata.json"} {
		for _, state := range []string{"missing", "empty", "directory"} {
			t.Run(name+"/"+state, func(t *testing.T) {
				cache := t.TempDir()
				db := filepath.Join(cache, "db")
				if err := os.Mkdir(db, 0755); err != nil {
					t.Fatal(err)
				}
				for _, file := range []string{"trivy.db", "metadata.json"} {
					path := filepath.Join(db, file)
					if file == name {
						switch state {
						case "missing":
							continue
						case "directory":
							if err := os.Mkdir(path, 0755); err != nil {
								t.Fatal(err)
							}
							continue
						case "empty":
							if err := os.WriteFile(path, nil, 0644); err != nil {
								t.Fatal(err)
							}
							continue
						}
					}
					if err := os.WriteFile(path, []byte("fixture"), 0644); err != nil {
						t.Fatal(err)
					}
				}
				err := Run(context.Background(), "sbom", cache, []string{"target.json"}, nil, io.Discard, io.Discard)
				if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "sync and build") {
					t.Fatalf("expected database error before starting Trivy, got %v", err)
				}
			})
		}
	}
}

func TestRunRejectsOldConversionPolicy(t *testing.T) {
	cache := t.TempDir()
	dir := filepath.Join(cache, "db")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(`{"Version":2}`), 0644); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(filepath.Join(dir, "trivy.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucket([]byte("ncsc-metadata"))
		if err != nil {
			return err
		}
		policy, err := json.Marshal(map[string]string{"version": "conversion-v1"})
		if err != nil {
			return err
		}
		return meta.Put([]byte("conversion-policy"), policy)
	})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), "sbom", cache, []string{"target.json"}, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "unsupported conversion policy") {
		t.Fatalf("old cache was not rejected before scanning: %v", err)
	}
}
