// Package scan runs Trivy with the local NCSC database and no upstream updates.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"io"
	"ncsc-trivy-db/internal/csaf"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

var managedFlags = []string{
	"--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update",
	"--offline-scan", "--skip-version-check", "--disable-telemetry",
}

// Arguments supplies the same NCSC-only settings for user scans and verification.
// Managed flags cannot be overridden by forwarded Trivy arguments.
func Arguments(command, cache string, args []string) ([]string, error) {
	switch command {
	case "sbom", "image", "fs", "rootfs", "repo":
	default:
		return nil, fmt.Errorf("unsupported scan command %q", command)
	}
	for _, arg := range args {
		if arg == "--" {
			break
		}
		name, _, _ := strings.Cut(arg, "=")
		if name == "--cache-dir" {
			return nil, fmt.Errorf("use --cache to select the NCSC database instead of --cache-dir")
		}
		if name == "--scanners" || slices.Contains(managedFlags, name) {
			return nil, fmt.Errorf("%s is managed by ncsc-trivy-db to use only the NCSC database", name)
		}
	}
	result := []string{command, "--cache-dir", cache}
	result = append(result, managedFlags...)
	result = append(result, "--scanners", "vuln")
	return append(result, args...), nil
}

// Run streams Trivy's input and output and preserves process errors and exit codes.
func Run(ctx context.Context, command, cache string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cache, err := filepath.Abs(cache)
	if err != nil {
		return err
	}
	argv, err := Arguments(command, cache, args)
	if err != nil {
		return err
	}
	for _, name := range []string{"trivy.db", "metadata.json"} {
		path := filepath.Join(cache, "db", name)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("NCSC database is unavailable; complete sync and build first: %w", err)
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("NCSC database file %s must be a nonempty regular file; complete sync and build first", path)
		}
	}
	// Check the conversion version stored in the database before scanning.
	db, e := bolt.Open(filepath.Join(cache, "db", "trivy.db"), 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if e != nil {
		return e
	}
	var buildPolicy struct {
		Version string `json:"version"`
	}
	e = db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("ncsc-metadata"))
		if meta == nil {
			return nil
		}
		raw := meta.Get([]byte("conversion-policy"))
		if len(raw) == 0 {
			return nil
		}
		return json.Unmarshal(raw, &buildPolicy)
	})
	db.Close()
	if e != nil {
		return fmt.Errorf("invalid conversion policy: %w", e)
	}
	if buildPolicy.Version != "" && buildPolicy.Version != csaf.PolicyVersion {
		return fmt.Errorf("unsupported conversion policy: %s", buildPolicy.Version)
	}
	cmd := exec.CommandContext(ctx, "trivy", argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
