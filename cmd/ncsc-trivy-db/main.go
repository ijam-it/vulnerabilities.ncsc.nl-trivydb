package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"ncsc-trivy-db/internal/build"
	"ncsc-trivy-db/internal/mirror"
)

func main() {
	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() > 0 {
			os.Exit(exitErr.ExitCode())
		}
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	return runArgs(os.Args[1:], os.Stdout, os.Stderr)
}

func runArgs(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printHelp(stdout)
		return nil
	}
	switch args[0] {
	case "-h", "--help", "-help", "help":
		if len(args) == 1 {
			printHelp(stdout)
			return nil
		}
		if args[0] != "help" || len(args) > 3 || (len(args) == 3 && args[1] != "scanning" && args[1] != "db" && args[1] != "coverage") {
			return fmt.Errorf("usage: ncsc-trivy-db help [command] [subcommand]")
		}
		args = append(args[1:], "--help")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "coverage":
		return coverageArgs(ctx, args[1:], stdout, stderr)
	case "benchmark":
		return benchmarkArgs(ctx, args[1:], stdout, stderr)
	case "scanning":
		return scanningArgs(ctx, args[1:], stdout, stderr)
	case "db":
		return dbArgs(ctx, args[1:], stdout, stderr)
	case "build":
		f := commandFlags("build", stdout, stderr)
		var o build.Options
		f.StringVar(&o.Mirror, "mirror", "data/ncsc.db", "resumable NCSC mirror database")
		f.StringVar(&o.Output, "output", "dist/ncsc", "output directory (replaced after a successful build)")
		f.BoolVar(&o.AllowPartial, "allow-partial", false, "development only: permit an incomplete mirror")
		f.BoolVar(&o.WaitForMirror, "wait", false, "wait until an active sync releases the mirror")
		f.DurationVar(&o.Validity, "validity", 24*time.Hour, "next update interval, measured from the source snapshot")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return fmt.Errorf("unexpected arguments: %v", f.Args())
		}
		_, err := build.Build(ctx, o)
		return err
	case "export-csaf":
		f := commandFlags("export-csaf", stdout, stderr)
		path := f.String("db", "dist/ncsc/db/trivy.db", "built Trivy database")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 1 {
			return fmt.Errorf("provide one CSAF path, e.g. 2021/cve-2021-44228.json")
		}
		return build.ExportCSAF(*path, f.Arg(0), stdout)
	case "sync":
		f := commandFlags("sync", stdout, stderr)
		var o mirror.Options
		f.StringVar(&o.Path, "mirror", "data/ncsc.db", "resumable NCSC mirror database")
		f.IntVar(&o.Workers, "workers", 32, "parallel HTTP workers (1..64)")
		f.Float64Var(&o.RequestsPerSecond, "requests-per-second", 30, "global HTTP request rate, capped at 30")
		f.IntVar(&o.Limit, "limit", 0, "development only: mirror just the first N documents (0=all)")
		f.BoolVar(&o.WaitForMirror, "wait", false, "wait for an active sync before fetching a fresh inventory")
		f.DurationVar(&o.ProgressInterval, "progress-interval", 5*time.Second, "time between progress updates (0=5s)")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return fmt.Errorf("unexpected arguments: %v", f.Args())
		}
		return mirror.Sync(ctx, o)
	default:
		return fmt.Errorf("unknown command %q; run 'ncsc-trivy-db help' for available commands", args[0])
	}
}
