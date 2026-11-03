package main

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestGeneralHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"-h"}, {"--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := runArgs(args, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"Usage:", "Typical workflow:", "help <command>",
				"sync", "build", "db", "export-csaf", "coverage",
				"scanning", "scanning sbom your-sbom.cdx.json",
				"Download or refresh", "Build a Trivy database",
				"Inspect and validate", "original CSAF document",
			} {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("help missing %q:\n%s", want, &stdout)
				}
			}
			if stderr.Len() != 0 {
				t.Errorf("unexpected stderr: %s", &stderr)
			}
			for _, target := range []string{"sbom", "image", "fs", "rootfs", "repo"} {
				if strings.Contains(stdout.String(), "\n  "+target+" ") {
					t.Errorf("scan target %q should not appear as a top-level command", target)
				}
			}
			for _, command := range []string{"audit", "verify", "status"} {
				if strings.Contains(stdout.String(), "\n  "+command+" ") {
					t.Errorf("db command %q should not appear at the top level", command)
				}
			}
			if strings.Contains(stdout.String(), "\n  coverage list ") {
				t.Error("coverage list should not appear as a top-level command")
			}
		})
	}
}

func TestCommandHelp(t *testing.T) {
	for _, tc := range []struct {
		name   string
		option string
		def    string
	}{
		{"coverage", "-cve", "dist/ncsc"},
		{"coverage list", "-after", "(default 20)"},
		{"benchmark", "-trivy-cache", "dist/trivy-official"},
		{"sync", "-workers", "(default 32)"},
		{"build", "-validity", "(default 24h0m0s)"},
		{"db audit", "-output", "dist/ncsc/db/trivy.db"},
		{"db verify", "-allow-partial", "dist/ncsc"},
		{"db status", "-mirror", "data/ncsc.db"},
		{"export-csaf", "-db", "dist/ncsc/db/trivy.db"},
		{"scanning sbom", "-cache", "dist/ncsc"},
		{"scanning image", "-cache", "dist/ncsc"},
		{"scanning fs", "-cache", "dist/ncsc"},
		{"scanning rootfs", "-cache", "dist/ncsc"},
		{"scanning repo", "-cache", "dist/ncsc"},
	} {
		parts := strings.Fields(tc.name)
		for _, args := range [][]string{append(append([]string{}, parts...), "-h"), append(append([]string{}, parts...), "--help"), append([]string{"help"}, parts...)} {
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				if err := runArgs(args, &stdout, &stderr); !errors.Is(err, flag.ErrHelp) {
					t.Fatalf("expected help without executing command; got %v", err)
				}
				for _, want := range []string{"Usage:", "ncsc-trivy-db " + tc.name, "Options:", "Example:", "--help", tc.option, tc.def} {
					if !strings.Contains(stdout.String(), want) {
						t.Errorf("help missing %q:\n%s", want, &stdout)
					}
				}
				if tc.name == "export-csaf" && !strings.Contains(stdout.String(), "<csaf-path>") {
					t.Error("export help must describe the required positional argument")
				}
				if stderr.Len() != 0 {
					t.Errorf("unexpected stderr: %s", &stderr)
				}
			})
		}
	}
}

func TestScanningHelp(t *testing.T) {
	for _, args := range [][]string{{"scanning"}, {"scanning", "--help"}, {"help", "scanning"}} {
		var stdout, stderr bytes.Buffer
		err := runArgs(args, &stdout, &stderr)
		if len(args) > 1 && !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("%v: expected help, got %v", args, err)
		}
		if len(args) == 1 && err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		for _, target := range []string{"sbom", "image", "fs", "rootfs", "repo"} {
			if !strings.Contains(stdout.String(), target) {
				t.Errorf("%v: missing %s", args, target)
			}
		}
	}
}

func TestDBHelp(t *testing.T) {
	for _, args := range [][]string{{"db"}, {"db", "--help"}, {"help", "db"}} {
		var stdout, stderr bytes.Buffer
		err := runArgs(args, &stdout, &stderr)
		if len(args) > 1 && !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("%v: expected help, got %v", args, err)
		}
		if len(args) == 1 && err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		for _, command := range []string{"audit", "verify", "status"} {
			if !strings.Contains(stdout.String(), command) {
				t.Errorf("%v: missing %s", args, command)
			}
		}
		if stderr.Len() != 0 {
			t.Errorf("%v: unexpected stderr %s", args, &stderr)
		}
	}
}

func TestInvalidHelp(t *testing.T) {
	for _, args := range [][]string{
		{"unknown"}, {"help", "unknown"}, {"help", "sync", "extra"}, {"--help", "sync"}, {"scanning", "unknown"}, {"db", "unknown"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runArgs(args, &stdout, &stderr)
			if err == nil || errors.Is(err, flag.ErrHelp) {
				t.Fatalf("expected an error, got %v", err)
			}
			if !strings.Contains(err.Error(), "help") {
				t.Errorf("error should point to help: %v", err)
			}
		})
	}
}
