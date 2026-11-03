package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"ncsc-trivy-db/internal/scan"
)

func scanningArgs(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printScanningHelp(stdout)
		return nil
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "-help" {
		if len(args) != 1 {
			return fmt.Errorf("usage: ncsc-trivy-db scanning <sbom|image|fs|rootfs|repo> [options] <target>")
		}
		printScanningHelp(stdout)
		return flag.ErrHelp
	}
	switch args[0] {
	case "sbom", "image", "fs", "rootfs", "repo":
		return scanArgs(ctx, args[0], args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown scanning command %q; run 'ncsc-trivy-db help scanning' for available commands", args[0])
	}
}

func scanArgs(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	cache, forwarded, err := parseScanArgs(command, args, stdout, stderr)
	if err != nil {
		return err
	}
	return scan.Run(ctx, command, cache, forwarded, os.Stdin, stdout, stderr)
}

// Parse only our cache selector; Trivy owns all other scan arguments.
func parseScanArgs(command string, args []string, stdout, stderr io.Writer) (string, []string, error) {
	cache := os.Getenv("NCSC_TRIVY_CACHE")
	if cache == "" {
		cache = "dist/ncsc"
	}
	f := commandFlags("scanning "+command, stdout, stderr)
	f.String("cache", cache, "built NCSC Trivy cache directory (also NCSC_TRIVY_CACHE)")
	var forwarded []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			forwarded = append(forwarded, args[i:]...)
			i = len(args)
		case arg == "-h" || arg == "--help" || arg == "-help":
			f.Usage()
			return "", nil, flag.ErrHelp
		case arg == "--cache" || arg == "-cache":
			i++
			if i == len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				return "", nil, fmt.Errorf("%s requires a cache directory", arg)
			}
			cache = args[i]
		case strings.HasPrefix(arg, "--cache=") || strings.HasPrefix(arg, "-cache="):
			_, cache, _ = strings.Cut(arg, "=")
			if cache == "" {
				return "", nil, fmt.Errorf("--cache requires a cache directory")
			}
		default:
			forwarded = append(forwarded, arg)
		}
	}
	if len(forwarded) == 0 || (len(forwarded) == 1 && forwarded[0] == "--") {
		return "", nil, fmt.Errorf("provide a scan target; run 'ncsc-trivy-db help scanning %s' for usage", command)
	}
	return cache, forwarded, nil
}
