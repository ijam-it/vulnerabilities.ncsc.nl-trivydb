package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

type commandHelp struct {
	name        string
	summary     string
	usage       string
	description string
	example     string
}

var commands = []commandHelp{
	{
		name:        "coverage",
		summary:     "Explain CVEs and products without Trivy package matches.",
		usage:       "coverage [options]",
		description: "Show stored CVE counts, package matches, and exclusion reasons.\nUse 'coverage list' for a paginated list of CVEs without package matches,\nor --cve for excluded and uncertain source product decisions. Matched and\nignored references are counted in CVE detail. Legacy builds explicitly\nreport when their conversion policy is unavailable.\n\nWorks offline with existing builds; no mirror, rebuild, or Trivy is required.\nThe large unmapped-products export is never read.",
		example:     "ncsc-trivy-db coverage --cve CVE-2021-44228",
	},
	{
		name:        "coverage list",
		summary:     "List CVEs without package matches.",
		usage:       "coverage list [options]",
		description: "Show CVEs without package matches in lexical order. Use --after\nwith the CVE printed on the previous page to continue.",
		example:     "ncsc-trivy-db coverage list --limit 10",
	},
	{
		name:        "benchmark",
		summary:     "Compare NCSC and official Trivy findings on an image or SBOM.",
		usage:       "benchmark <image|sbom|conversion> [options] [target]",
		description: "Image and SBOM modes scan one frozen inventory with NCSC and official\nTrivy databases. The output shows shared and exclusive findings, scan-recognized\npackage counts, and SBOM component identifiers. Full differences are saved in\ndifferences.txt and report.json. An SBOM with components but no Trivy-recognized\npackages is reported as an unscanned inventory, not equal coverage. Image mode\nalso validates direct image-scan parity. Each output directory must be new.\n\nConversion mode compares two report.json files directly, including added/lost\nNCSC findings and uncertain candidates. It requires matching inputs and source\nsnapshots. Options: --before-report, --after-report, --before-cache,\n--after-cache, --output (a new JSON file).",
		example:     "ncsc-trivy-db benchmark image --output dist/comparison node:20.18.0-bookworm-slim",
	},
	{
		name:        "sync",
		summary:     "Download or refresh the NCSC advisory mirror.",
		usage:       "sync [options]",
		description: "Fetch the full NCSC CSAF inventory and download its advisories into a local\nmirror. Completed downloads are reused when resuming or refreshing a sync.\nRequires internet access; the initial download can take several hours.",
		example:     "ncsc-trivy-db sync --progress-interval 1s",
	},
	{
		name:        "build",
		summary:     "Build a Trivy database from the local mirror.",
		usage:       "build [options]",
		description: "Convert a complete NCSC mirror into a Trivy cache directory with archived\nsource, candidate index, coverage report, and checksums. Existing output is\nreplaced after a successful build. Partial mirrors require --allow-partial.\nUnknown affected version ranges are indexed as uncertain candidates and do\nnot produce scan findings.",
		example:     "ncsc-trivy-db build --output dist/ncsc-next",
	},
	{
		name:        "db audit",
		summary:     "Compare a built database against the full mirror.",
		usage:       "db audit [options]",
		description: "Check archived source documents, CVEs, checksums, and package advisories\nagainst the mirror inventory. Reject extra records and non-NCSC sources.\nWrite the audit report as JSON to stdout, or to --output when provided.",
		example:     "ncsc-trivy-db db audit --output audit.json",
	},
	{
		name:        "db verify",
		summary:     "Check database integrity and run offline Trivy scan controls.",
		usage:       "db verify [options]",
		description: "Validate checksums, archive entries, and the database schema, then use Trivy\nto scan affected and fixed package controls. Requires Trivy to be installed.\nSave scan results and verification.json in the cache directory after success.",
		example:     "ncsc-trivy-db db verify --cache dist/ncsc",
	},
	{
		name:        "db status",
		summary:     "Print the local mirror's snapshot summary as JSON.",
		usage:       "db status [options]",
		description: "Read snapshot and completeness information from an existing, closed mirror.\nFor an active sync, use the progress updates printed by the sync command.",
		example:     "ncsc-trivy-db db status --mirror data/ncsc.db",
	},
	{
		name:        "db",
		summary:     "Inspect and validate the mirror and built database.",
		usage:       "db <audit|verify|status> [options]",
		description: "Inspect the mirror snapshot, compare a build with its source mirror, or\nverify the built database. Run 'ncsc-trivy-db help db <command>' for details.",
		example:     "ncsc-trivy-db db status",
	},
	{
		name:        "export-csaf",
		summary:     "Extract an original CSAF document from a built database.",
		usage:       "export-csaf [options] <csaf-path>",
		description: "Write the exact original CSAF JSON to stdout without network requests.\nProvide one path from the NCSC inventory, such as 2021/cve-2021-44228.json.\nPlace options before the CSAF path.",
		example:     "ncsc-trivy-db export-csaf --db dist/ncsc/db/trivy.db 2021/cve-2021-44228.json > log4shell.csaf.json",
	},
	{
		name:        "scanning",
		summary:     "Scan an SBOM, image, filesystem, rootfs, or repository.",
		usage:       "scanning <sbom|image|fs|rootfs|repo> [options] <target>",
		description: "Scan a target with the built NCSC database. Run 'ncsc-trivy-db help\nscanning <target>' for target-specific options and examples.",
		example:     "ncsc-trivy-db scanning sbom your-sbom.cdx.json",
	},
	scanHelp("sbom", "Scan an SBOM using the NCSC database.", "sbom-path", "your-sbom.cdx.json"),
	scanHelp("image", "Scan a container image using the NCSC database.", "image", "your-image:tag"),
	scanHelp("fs", "Scan a filesystem using the NCSC database.", "path", "."),
	scanHelp("rootfs", "Scan a root filesystem using the NCSC database.", "path", "/path/to/rootfs"),
	scanHelp("repo", "Scan a repository using the NCSC database.", "repository", "https://github.com/example/project"),
}

func scanHelp(name, summary, target, example string) commandHelp {
	return commandHelp{
		name: "scanning " + name, summary: summary,
		usage:       "scanning " + name + " [--cache directory] [trivy options] <" + target + ">",
		description: "Run the installed Trivy with a built NCSC cache and vulnerability scanning.\nUpstream database, Java index, and VEX repository updates are disabled, along\nwith online package lookups, version checks, and telemetry. Image pulls and\nrepository downloads may still use the network.\n\nUse --cache or NCSC_TRIVY_CACHE to select the cache (default dist/ncsc, relative\nto the working directory). Other arguments are forwarded to Trivy; see\n'Trivy options' below. Use -- before targets beginning with a dash.",
		example:     "ncsc-trivy-db scanning " + name + " " + example,
	}
}

func printHelp(w io.Writer) {
	fmt.Fprintln(w, "Build, inspect, and scan with an NCSC-only Trivy vulnerability database.")
	fmt.Fprintln(w, "\nUsage:\n  ncsc-trivy-db <command> [options]")
	fmt.Fprintln(w, "\nCommands:")
	for _, command := range commands {
		if strings.HasPrefix(command.name, "scanning ") || strings.HasPrefix(command.name, "db ") || command.name == "coverage list" {
			continue
		}
		fmt.Fprintf(w, "  %-13s %s\n", command.name, command.summary)
	}
	fmt.Fprintf(w, "  %-13s %s\n", "help", "Show general help or help for a command.")
	fmt.Fprintln(w, "\nTypical workflow:\n  ncsc-trivy-db sync\n  ncsc-trivy-db build\n  ncsc-trivy-db db audit\n  ncsc-trivy-db db verify\n  ncsc-trivy-db scanning sbom your-sbom.cdx.json")
	fmt.Fprintln(w, "\nRun 'ncsc-trivy-db help <command>' or 'ncsc-trivy-db <command> --help'\nfor command details, options, defaults, and an example.")
}

func printScanningHelp(w io.Writer) {
	fmt.Fprintln(w, "Scan targets using the NCSC database.")
	fmt.Fprintln(w, "\nUsage:\n  ncsc-trivy-db scanning <sbom|image|fs|rootfs|repo> [options] <target>")
	fmt.Fprintln(w, "\nTargets:")
	for _, command := range commands {
		if name, ok := strings.CutPrefix(command.name, "scanning "); ok {
			fmt.Fprintf(w, "  %-8s %s\n", name, command.summary)
		}
	}
	fmt.Fprintln(w, "\nRun 'ncsc-trivy-db help scanning <target>' for options and examples.")
}

func printDBHelp(w io.Writer) {
	fmt.Fprintln(w, "Inspect and validate the NCSC mirror and built database.")
	fmt.Fprintln(w, "\nUsage:\n  ncsc-trivy-db db <audit|verify|status> [options]")
	fmt.Fprintln(w, "\nCommands:")
	for _, command := range commands {
		if name, ok := strings.CutPrefix(command.name, "db "); ok {
			fmt.Fprintf(w, "  %-8s %s\n", name, command.summary)
		}
	}
	fmt.Fprintln(w, "\nRun 'ncsc-trivy-db help db <command>' for options and examples.")
}

func commandFlags(name string, stdout, stderr io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(stderr)
	for _, command := range commands {
		if command.name != name {
			continue
		}
		f.Usage = func() {
			fmt.Fprintf(stdout, "%s\n\nUsage:\n  ncsc-trivy-db %s\n\n%s\n\nOptions:\n", command.summary, command.usage, command.description)
			f.SetOutput(stdout)
			f.PrintDefaults()
			f.SetOutput(stderr)
			fmt.Fprintln(stdout, "  -h, --help\n    \tShow help for this command.")
			if name, ok := strings.CutPrefix(command.name, "scanning "); ok {
				fmt.Fprintf(stdout, "\nTrivy options:\n  Forward options such as --format json, --output report.json, or --exit-code 1.\n  Cache and NCSC scan settings are managed by this CLI and cannot be overridden.\n  Run 'trivy %s --help' for the full list of Trivy options.\n", name)
			}
			fmt.Fprintf(stdout, "\nExample:\n  %s\n", command.example)
		}
		break
	}
	return f
}
