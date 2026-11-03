# Development

Run commands from the repository root. The project uses Go 1.25 or newer and
Make. Trivy on your `PATH` is needed for scans, database verification, and
benchmarks; compiling the CLI and running the Go tests do not require it.

## Build and run the CLI

```sh
make build
./bin/ncsc-trivy-db help
./bin/ncsc-trivy-db sync --help
```

`make build` compiles the CLI to `bin/ncsc-trivy-db`. It does not download
advisories or build a vulnerability database. To compile without Make:

```sh
go build -trimpath -o bin/ncsc-trivy-db ./cmd/ncsc-trivy-db
```

## Find your way around

| Path | What lives here |
| --- | --- |
| `cmd/ncsc-trivy-db/` | CLI entry point, flags, help, and command dispatch |
| `internal/mirror/` | NCSC downloads, resumable local mirror, rate limiting, and progress |
| `internal/csaf/` | CSAF parsing, package identity, version ranges, and conversion policy |
| `internal/build/` | Trivy database generation, archived source, coverage reports, and checksums |
| `internal/scan/` | Trivy invocation and NCSC scan settings |
| `internal/coverage/` | Coverage summaries and per-CVE conversion explanations |
| `internal/audit/` | Checks a built database against its source mirror |
| `internal/verify/` | Integrity checks and affected/fixed Trivy scan controls |
| `internal/benchmark/` | NCSC versus official DB comparisons and before/after conversion comparisons |
| `examples/` | Small SBOMs for manual scans |
| `testdata/ncsc/` | Frozen CSAF fixtures; see its `README.md` for provenance |
| `benchmarks.md` | Comparison workflow and interpretation |

Tests live beside the Go files they exercise as `*_test.go`.

## Test changes

```sh
make test
go test ./internal/csaf ./internal/build
go test ./cmd/ncsc-trivy-db ./internal/scan
```

`make test` runs `go test ./...`. Use the narrower commands when working on
conversion or CLI/scan behavior. Format changed Go files with `gofmt`.

When changing conversion rules, start in `internal/csaf/` and add cases using
the frozen fixtures in `testdata/ncsc/`. Check both affected and fixed versions.
Rebuild the vulnerability database to exercise converter changes; recompiling
the CLI alone does not update an existing database.

## Build a vulnerability database

The complete pipeline downloads or refreshes the mirror twice to catch changes
during the initial download, then builds, audits, and verifies a new database:

```sh
make full-build
```

The initial sync can take hours; completed downloads are reused on later runs.
Run only one sync at a time per shared public IP to stay within NCSC's request
limits. A successful build replaces the output directory, including old audit
and verification results. `make full-build` defaults to `dist/ncsc`, matching
the scanner default. To keep a previous build, choose another directory with
`make full-build BUILD_DIR=dist/ncsc-next`.

To run each step yourself, or rebuild from an existing complete mirror:

```sh
./bin/ncsc-trivy-db sync
./bin/ncsc-trivy-db build --output dist/ncsc-next
./bin/ncsc-trivy-db db audit --db dist/ncsc-next/db/trivy.db --output dist/ncsc-next/audit.json
./bin/ncsc-trivy-db db verify --cache dist/ncsc-next
./bin/ncsc-trivy-db scanning sbom --cache dist/ncsc-next examples/affected.cdx.json
```

Skip `sync` when rebuilding from an unchanged mirror. Use
`./bin/ncsc-trivy-db db status` to inspect the local mirror snapshot.
For a small development build, use a separate mirror and output directory:

```sh
./bin/ncsc-trivy-db sync --mirror data/dev.db --limit 100
./bin/ncsc-trivy-db build --mirror data/dev.db --allow-partial --output dist/dev
```

This is an incomplete dataset for development; full builds require a complete
mirror.

## Find generated files

`bin/`, `data/`, and `dist/` are ignored by Git. The default mirror is
`data/ncsc.db`. A database build writes these files under its output directory:

| Path | Contents |
| --- | --- |
| `db/trivy.db`, `db/metadata.json` | Trivy database and metadata |
| `db.tar.gz`, `SHA256SUMS` | Distributable archive and checksums |
| `coverage.json` | Conversion policy, source identity, and outcome counts |
| `unmapped-products.ndjson.gz` | Excluded product/status references |
| `audit.json` | Source completeness and integrity report, written by audit |
| `verification.json`, `verification-results/` | Verification report and scan controls, written by verify |

Scans default to `dist/ncsc` relative to the working directory. Set
`NCSC_TRIVY_CACHE` or pass `--cache` to choose another build; the flag wins.
The scanner forwards Trivy options and preserves its exit code. It disables
upstream DB, Java index, and VEX updates, online package lookups, version
checks, and telemetry. Image pulls and repository downloads may still use
the network. See `./bin/ncsc-trivy-db help scanning sbom` for supported options.

## Inspect conversion results

```sh
./bin/ncsc-trivy-db coverage --cache dist/ncsc-next
./bin/ncsc-trivy-db coverage list --cache dist/ncsc-next --limit 10
./bin/ncsc-trivy-db coverage --cache dist/ncsc-next --cve CVE-2021-44228 --format json
./bin/ncsc-trivy-db export-csaf --db dist/ncsc-next/db/trivy.db 2021/cve-2021-44228.json
```

All source advisories are archived, but findings require a supported package
identity and an explicit affected version range that Trivy can enforce.
The `conversion-v2` policy keeps identified packages with unspecified affected
versions as uncertain candidates in `ncsc-candidates`; they do not produce
scan findings. Conversion decisions live in `internal/csaf/`, including APK
version comparison and Alpine source-package handling.

Coverage details explain excluded and uncertain product references; reason
counts are references, not unique CVEs. Use the `--after` cursor printed by
`coverage list` for the next page. These commands work offline against a built
database without reading the large exclusion export.

For NCSC versus official Trivy DB comparisons and saved report locations,
follow [benchmarks.md](benchmarks.md).
