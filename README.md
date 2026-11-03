# NCSC Trivy database

A vibecoded experiment to see whether advisories from
[vulnerabilities.ncsc.nl](https://vulnerabilities.ncsc.nl/) can be used as a
Trivy vulnerability database, and how its findings compare with the official
Trivy DB.

It downloads NCSC Netherlands' CSAF advisories, converts usable package and
version information into a database, and scans with standard Trivy. No Trivy
fork is required. This is an exploratory project: coverage depends on what the
NCSC advisories describe and what the converter can match. A clean scan does
not mean every NCSC advisory has been checked.

See [From CSAF advisories to Trivy findings](conversion.md) for a plain-language
explanation of how package identities, affected versions, and vulnerability
details are translated, with examples and coverage limitations.

## Run it

You need Go 1.25 or newer, Make, Trivy on your `PATH` (tested with 0.74.0),
internet access, and disk space for the advisory mirror and database.
Run commands from the repository root.

First, compile the CLI and create the NCSC database:

```sh
make full-build
```

The initial download can take several hours. This command downloads the
advisories, builds the database, then audits and verifies it. Interrupted
downloads can be resumed by rerunning the command. A successful build replaces
the existing database output directory (default `dist/ncsc`).

Once the database is ready, scan the included example or your own target:

```sh
./bin/ncsc-trivy-db scanning sbom examples/affected.cdx.json
./bin/ncsc-trivy-db scanning sbom your-sbom.cdx.json
./bin/ncsc-trivy-db scanning image your-image:tag
```

Scans use `dist/ncsc` by default. For another build, add `--cache` before the
target, for example:

```sh
./bin/ncsc-trivy-db scanning sbom --cache dist/ncsc-next your-sbom.cdx.json
```

## Compare with the official Trivy DB

The `benchmark` command scans the same inventory with the NCSC database and
the official Trivy DB, then reports shared findings, findings unique to each,
and severity or fix differences:

```sh
trivy image --cache-dir dist/trivy-official --download-db-only
./bin/ncsc-trivy-db benchmark sbom --output dist/comparison your-sbom.cdx.json
```

Read `dist/comparison/differences.txt` for the differences and `report.json`
for the full results. Each comparison needs a new output directory. These
comparisons show differences in findings, not which database is correct.
See [benchmarks.md](benchmarks.md) for more comparison commands and limitations.

For compiling the binary, tests, and a map of the code and generated files,
see [dev.md](dev.md).
