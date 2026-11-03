package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"ncsc-trivy-db/internal/audit"
	"ncsc-trivy-db/internal/mirror"
	"ncsc-trivy-db/internal/verify"
)

func dbArgs(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printDBHelp(stdout)
		return nil
	}
	switch args[0] {
	case "-h", "--help", "-help":
		if len(args) != 1 {
			return fmt.Errorf("usage: ncsc-trivy-db db <audit|verify|status> [options]")
		}
		printDBHelp(stdout)
		return flag.ErrHelp
	case "verify":
		f := commandFlags("db verify", stdout, stderr)
		cache := f.String("cache", "dist/ncsc", "built Trivy cache directory")
		allowPartial := f.Bool("allow-partial", false, "development only: verify a partial build")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return fmt.Errorf("unexpected arguments: %v", f.Args())
		}
		_, err := verify.Check(ctx, *cache, *allowPartial, stdout)
		return err
	case "audit":
		f := commandFlags("db audit", stdout, stderr)
		mirrorPath := f.String("mirror", "data/ncsc.db", "complete NCSC mirror database")
		databasePath := f.String("db", "dist/ncsc/db/trivy.db", "built Trivy database")
		output := f.String("output", "", "optional audit report JSON file (default stdout)")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return fmt.Errorf("unexpected arguments: %v", f.Args())
		}
		r, err := audit.Check(ctx, *mirrorPath, *databasePath)
		if err != nil {
			return err
		}
		writer := stdout
		if *output != "" {
			file, err := os.Create(*output)
			if err != nil {
				return err
			}
			defer file.Close()
			writer = file
		}
		enc := json.NewEncoder(writer)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "status":
		f := commandFlags("db status", stdout, stderr)
		path := f.String("mirror", "data/ncsc.db", "NCSC mirror database")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		db, err := mirror.Open(*path, true)
		if err != nil {
			return err
		}
		defer db.Close()
		s, err := mirror.ReadSnapshot(db)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(s)
	default:
		return fmt.Errorf("unknown db command %q; run 'ncsc-trivy-db help db' for available commands", args[0])
	}
}
