package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"ncsc-trivy-db/internal/benchmark"
)

func benchmarkArgs(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "conversion" {
		f := commandFlags("benchmark", stdout, stderr)
		beforeReport := f.String("before-report", "", "baseline benchmark report.json")
		afterReport := f.String("after-report", "", "new benchmark report.json")
		beforeCache := f.String("before-cache", "", "baseline NCSC cache")
		afterCache := f.String("after-cache", "", "new NCSC cache")
		output := f.String("output", "", "new conversion comparison JSON file")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *beforeReport == "" || *afterReport == "" || *beforeCache == "" || *afterCache == "" || *output == "" || f.NArg() != 0 {
			return fmt.Errorf("usage: benchmark conversion --before-report FILE --after-report FILE --before-cache DIR --after-cache DIR --output FILE")
		}
		diff, e := benchmark.CompareConversion(ctx, *beforeReport, *afterReport, *beforeCache, *afterCache)
		if e != nil {
			return e
		}
		file, e := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if e != nil {
			return e
		}
		defer file.Close()
		enc := json.NewEncoder(file)
		enc.SetIndent("", "  ")
		if e = enc.Encode(diff); e != nil {
			return e
		}
		fmt.Fprintf(stdout, "Conversion comparison: %d added, %d removed, %d metadata changes, %d candidates added; details: %s\n", len(diff.Added), len(diff.Removed), len(diff.MetadataChanges), len(diff.CandidatesAdded), *output)
		return nil
	}
	var o benchmark.Options
	f := commandFlags("benchmark", stdout, stderr)
	f.StringVar(&o.NCSCCache, "ncsc-cache", "dist/ncsc", "built NCSC cache directory")
	f.StringVar(&o.TrivyCache, "trivy-cache", "dist/trivy-official", "official Trivy cache directory (download separately)")
	f.StringVar(&o.Output, "output", "", "new report directory (required)")
	f.StringVar(&o.Platform, "platform", "linux/amd64", "image platform")
	f.DurationVar(&o.Timeout, "timeout", 10*time.Minute, "timeout per Trivy process")
	if len(args) > 0 && (args[0] == "image" || args[0] == "sbom") {
		o.Kind, args = args[0], args[1:]
	}
	if err := f.Parse(args); err != nil {
		return err
	}
	if o.Kind == "" || f.NArg() != 1 {
		return fmt.Errorf("usage: ncsc-trivy-db benchmark <image|sbom> [options] <target>; run 'ncsc-trivy-db help benchmark'")
	}
	o.Target = f.Arg(0)
	_, err := benchmark.Run(ctx, o, stdout)
	return err
}
