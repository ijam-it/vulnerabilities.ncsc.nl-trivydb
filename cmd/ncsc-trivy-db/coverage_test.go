package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCoverageInvalidOptions(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--cve", "bad"}, "invalid CVE"},
		{[]string{"list", "--limit", "0"}, "positive"},
		{[]string{"--format", "csv"}, "text or json"},
		{[]string{"list", "--after", "bad"}, "invalid CVE"},
		{[]string{"--after", "CVE-2026-1000"}, "flag provided but not defined"},
		{[]string{"--status", "all"}, "flag provided but not defined"},
		{[]string{"--products", "all"}, "flag provided but not defined"},
		{[]string{"--offset", "1"}, "flag provided but not defined"},
		{[]string{"list", "--cve", "CVE-2026-1000"}, "flag provided but not defined"},
		{[]string{"CVE-2026-1000"}, "coverage --cve"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runArgs(append([]string{"coverage"}, tc.args...), &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wanted %q, got %v", tc.want, err)
			}
			if stdout.Len() != 0 && !strings.Contains(err.Error(), "flag provided but not defined") {
				t.Fatalf("unexpected output: %s", &stdout)
			}
		})
	}
}
