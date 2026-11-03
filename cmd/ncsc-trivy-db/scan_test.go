package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Reuse the test executable as both the CLI and a stand-in Trivy process so
// the integration test exercises main's exit handling without a shell script.
func TestMain(m *testing.M) {
	if os.Getenv("NCSC_TEST_CLI") == "1" {
		if filepath.Base(os.Args[0]) == "trivy" {
			input, _ := io.ReadAll(os.Stdin)
			_ = json.NewEncoder(os.Stdout).Encode(struct {
				Args  []string
				Input string
			}{os.Args[1:], string(input)})
			fmt.Fprintln(os.Stderr, "Trivy diagnostic")
			code, _ := strconv.Atoi(os.Getenv("NCSC_TEST_EXIT"))
			os.Exit(code)
		}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestParseScanArgs(t *testing.T) {
	t.Setenv("NCSC_TRIVY_CACHE", "")
	for _, tc := range []struct {
		args      []string
		cache     string
		forwarded []string
	}{
		{[]string{"target.json"}, "dist/ncsc", []string{"target.json"}},
		{[]string{"--cache", "cache with spaces", "--format", "json", "target.json"}, "cache with spaces", []string{"--format", "json", "target.json"}},
		{[]string{"target.json", "--cache=custom", "--exit-code", "7"}, "custom", []string{"target.json", "--exit-code", "7"}},
		{[]string{"--", "--cache=target"}, "dist/ncsc", []string{"--", "--cache=target"}},
	} {
		cache, args, err := parseScanArgs("sbom", tc.args, io.Discard, io.Discard)
		if err != nil || cache != tc.cache || !slices.Equal(args, tc.forwarded) {
			t.Errorf("%v: got cache=%q, args=%v, error=%v", tc.args, cache, args, err)
		}
	}
	t.Setenv("NCSC_TRIVY_CACHE", "environment-cache")
	for _, tc := range []struct {
		args  []string
		cache string
	}{
		{[]string{"target.json"}, "environment-cache"},
		{[]string{"--cache", "explicit-cache", "target.json"}, "explicit-cache"},
	} {
		cache, _, err := parseScanArgs("sbom", tc.args, io.Discard, io.Discard)
		if err != nil || cache != tc.cache {
			t.Fatalf("cache precedence: got %q, %v; want %q", cache, err, tc.cache)
		}
	}
	for _, args := range [][]string{nil, {"--"}, {"--cache"}, {"--cache="}, {"--cache", "--format", "json"}} {
		if _, _, err := parseScanArgs("sbom", args, io.Discard, io.Discard); err == nil {
			t.Errorf("accepted missing cache or target: %v", args)
		}
	}
}

func TestScanCLI(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache with spaces")
	if err := os.MkdirAll(filepath.Join(cache, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(filepath.Join(cache, "db", "trivy.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(cache, "db", "metadata.json"), []byte("fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(dir, "trivy")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"sbom", "image", "fs", "rootfs", "repo"} {
		for _, code := range []int{0, 23} {
			t.Run(fmt.Sprintf("%s/exit-%d", command, code), func(t *testing.T) {
				cmd := exec.Command(executable, "scanning", command, "--cache", cache, "--format", "json", "--exit-code", strconv.Itoa(code), "target with spaces")
				cmd.Env = append(os.Environ(), "NCSC_TEST_CLI=1", "NCSC_TEST_EXIT="+strconv.Itoa(code), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
				cmd.Stdin = strings.NewReader("scan input")
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				output, err := cmd.Output()
				if code == 0 {
					if err != nil {
						t.Fatalf("CLI failed: %v\n%s", err, &stderr)
					}
				} else {
					var exitErr *exec.ExitError
					if !errors.As(err, &exitErr) || exitErr.ExitCode() != code {
						t.Fatalf("exit code: got %v, want %d; %s", err, code, &stderr)
					}
				}
				var got struct {
					Args  []string
					Input string
				}
				if err := json.Unmarshal(output, &got); err != nil {
					t.Fatalf("invalid output: %v\n%s", err, output)
				}
				if got.Input != "scan input" || stderr.String() != "Trivy diagnostic\n" {
					t.Fatalf("streams changed: input=%q stderr=%q", got.Input, &stderr)
				}
				if !slices.Equal(got.Args[:3], []string{command, "--cache-dir", cache}) ||
					!slices.Equal(got.Args[len(got.Args)-5:], []string{"--format", "json", "--exit-code", strconv.Itoa(code), "target with spaces"}) {
					t.Fatalf("arguments changed: %v", got.Args)
				}
				for _, flag := range []string{"--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update", "--offline-scan", "--skip-version-check", "--disable-telemetry"} {
					if !slices.Contains(got.Args, flag) {
						t.Errorf("missing NCSC flag %s", flag)
					}
				}
				idx := slices.Index(got.Args, "--scanners")
				if idx < 0 || idx+1 >= len(got.Args) || got.Args[idx+1] != "vuln" {
					t.Fatalf("vulnerability scanner not selected: %v", got.Args)
				}
			})
		}
	}
}
