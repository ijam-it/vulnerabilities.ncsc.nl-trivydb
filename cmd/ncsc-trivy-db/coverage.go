package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"ncsc-trivy-db/internal/coverage"
)

func coverageArgs(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	listing := len(args) > 0 && args[0] == "list"
	name := "coverage"
	if listing {
		name = "coverage list"
		args = args[1:]
	}
	f := commandFlags(name, stdout, stderr)
	defaultCache := os.Getenv("NCSC_TRIVY_CACHE")
	if defaultCache == "" {
		defaultCache = "dist/ncsc"
	}
	cache := f.String("cache", defaultCache, "built NCSC cache directory (also NCSC_TRIVY_CACHE)")
	var cve *string
	var after *string
	var limit *int
	if listing {
		after = f.String("after", "", "list CVEs after this CVE cursor, in lexical order")
		limit = f.Int("limit", 20, "maximum CVEs per page")
	} else {
		cve = f.String("cve", "", "explain one CVE, e.g. CVE-2021-44228")
	}
	format := f.String("format", "text", "output format: text, json")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v; use coverage list or coverage --cve CVE-YYYY-NNNN", f.Args())
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("--format must be text or json")
	}
	var validationErr error
	if listing {
		if *limit < 1 {
			return fmt.Errorf("--limit must be positive")
		}
		if *after != "" {
			*after, validationErr = coverage.CVE(*after)
			if validationErr != nil {
				return validationErr
			}
		}
	} else if *cve != "" {
		*cve, validationErr = coverage.CVE(*cve)
		if validationErr != nil {
			return validationErr
		}
	}
	r, err := coverage.Open(*cache)
	if err != nil {
		return err
	}
	defer r.Close()
	encode := func(value any) error {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	}
	if !listing && *cve != "" {
		d, err := r.Detail(ctx, *cve)
		if err != nil {
			return err
		}
		if *format == "json" {
			return encode(d)
		}
		fmt.Fprintf(stdout, "%s: %s\nSource: %s\nConversion policy: %s\nStored package advisories: %d\nProduct references: %d matched, %d uncertain, %d excluded, %d ignored\n", d.CVE, d.Title, d.Source, d.PolicyVersion, d.Advisories, d.Matched, d.Uncertain, d.Excluded, d.Ignored)
		if !d.PolicyAvailable {
			fmt.Fprintln(stdout, "This older build has no recorded conversion policy; decision explanations may be unavailable.")
		}
		if d.Matched == 0 {
			fmt.Fprintln(stdout, "The CVE source is stored, but it has no matchable product references.")
		}
		if d.Matched > 0 && d.Excluded > 0 {
			fmt.Fprintln(stdout, "Coverage is partial: some product references cannot be matched.")
		}
		printReasons(stdout, d.Reasons)
		fmt.Fprintf(stdout, "\nExcluded and uncertain product references: %d\n", len(d.Products))
		for _, p := range d.Products {
			fmt.Fprintf(stdout, "\n  %s [%s; %s] %s\n", p.ID, p.Status, p.Outcome, p.Source.Name)
			if p.Reason != "" {
				fmt.Fprintf(stdout, "    %s: %s\n", p.Reason, p.Explanation)
			}
			for _, field := range []struct{ name, value string }{{"Package", p.PackageName}, {"Version/range", p.Version}, {"Vendor", p.Vendor}, {"Family", p.Family}, {"PURL", p.Source.Helper.PURL}, {"CPE", p.Source.Helper.CPE}} {
				if field.value != "" {
					fmt.Fprintf(stdout, "    %s: %s\n", field.name, field.value)
				}
			}
			if p.Candidate != nil {
				fmt.Fprintf(stdout, "    Candidate: %s / %s; rule %s; affected versions unspecified\n    Source SHA-256: %s\n", p.Candidate.Bucket, p.Candidate.Package, p.Candidate.RuleID, p.Candidate.CSAFSHA256)
			}
		}
		return nil
	}
	if listing {
		page, err := r.List(ctx, *after, *limit)
		if err != nil {
			return err
		}
		if *format == "json" {
			return encode(page)
		}
		fmt.Fprintf(stdout, "CVEs without package matches (lexical order): %d shown\n", len(page.Rows))
		w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "CVE\tADVISORIES\tUNCERTAIN REFS\tEXCLUDED REFS\tIGNORED REFS\tEXCLUSION REASONS")
		for _, row := range page.Rows {
			var reasons []string
			for _, reason := range sortedReasons(row.Reasons) {
				reasons = append(reasons, fmt.Sprintf("%s=%d", reason, row.Reasons[reason]))
			}
			if len(reasons) == 0 && row.Uncertain > 0 {
				reasons = append(reasons, "affected versions unspecified")
			} else if len(reasons) == 0 && row.Advisories == 0 {
				reasons = append(reasons, "no usable affected-package observations")
			}
			fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%s\n", row.CVE, row.Advisories, row.Uncertain, row.Excluded, row.Ignored, strings.Join(reasons, ", "))
		}
		if err := w.Flush(); err != nil {
			return err
		}
		if page.NextAfter != "" {
			fmt.Fprintf(stdout, "\nNext page: coverage list --after %s --limit %d\n", page.NextAfter, *limit)
		}
		fmt.Fprintln(stdout, "\nInspect a CVE with: coverage --cve CVE-YYYY-NNNN")
		return nil
	}
	s, err := r.Summary(ctx)
	if err != nil {
		return err
	}
	if *format == "json" {
		return encode(s)
	}
	fmt.Fprintf(stdout, "CVE records stored:          %d\nWith package matches:        %d\nWithout package matches:     %d\nStored package advisories:   %d\nSource snapshot complete:    %t (%d indexed documents)\n", s.CVEs, s.WithMatches, s.WithoutMatches, s.Advisories, s.SourceComplete, s.SourceIndexed)
	fmt.Fprintln(stdout, "\nCVE records and original source are retained even when products cannot be matched.\nA CVE with matches can still have excluded products. Counts are relative to this snapshot, not all published CVEs.")
	if s.ReasonsAvailable {
		fmt.Fprintf(stdout, "Conversion policy:           %s\nUncertain candidates:        %d\n", s.PolicyVersion, s.UncertainCandidates)
		fmt.Fprintf(stdout, "\nExcluded product references: %d\n", s.ExcludedProducts)
		printReasons(stdout, s.Reasons)
	} else {
		fmt.Fprintln(stdout, "\nBuild-time exclusion totals unavailable; coverage.json or metadata.json is absent. CVE details still work.")
	}
	fmt.Fprintln(stdout, "\nReasons count source product/status references, not unique CVEs or packages.\nCVE details show excluded and uncertain product references, plus counts for matched and ignored references.\n\nList CVEs without matches: coverage list\nInspect a CVE:             coverage --cve CVE-2021-44228\nMachine-readable output:  add --format json")
	return nil
}

func sortedReasons(reasons map[string]int) []string {
	keys := make([]string, 0, len(reasons))
	for reason := range reasons {
		keys = append(keys, reason)
	}
	sort.Slice(keys, func(i, j int) bool {
		if reasons[keys[i]] != reasons[keys[j]] {
			return reasons[keys[i]] > reasons[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

func printReasons(w io.Writer, reasons map[string]int) {
	for _, reason := range sortedReasons(reasons) {
		fmt.Fprintf(w, "  %d  %s\n    %s\n", reasons[reason], reason, coverage.Explain(reason))
	}
}
