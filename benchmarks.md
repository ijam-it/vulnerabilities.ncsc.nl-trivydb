# Run the database benchmarks

Each command scans one fixed image with the **same
Trivy executable** and two separate database snapshots: our NCSC build and the
official Trivy DB. Run them one at a time. The CLI prints the shared findings,
findings unique to each DB, and severity/fix differences; each output directory
also gets `differences.txt`, the full `report.json`, and raw scan reports.

## Prepare

Run from the repository root with Go and Trivy installed:

```sh
make build
trivy image --cache-dir dist/trivy-official --download-db-only
NCSC_CACHE=dist/ncsc
RUN="dist/benchmarks/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN"
```

`make build` recompiles the CLI; it does **not** rebuild the NCSC database. Set
`NCSC_CACHE` to the build you want to compare. If you need a new build from the
current converter, run `make full-build BUILD_DIR=dist/ncsc-benchmark` and set
`NCSC_CACHE=dist/ncsc-benchmark`. The initial mirror download can take hours.
Each report records both database hashes.

The image references below are pinned by digest. The NCSC and official DB hashes
and the generated SBOM hash are recorded in each report so a later run can be distinguished.

## Run each target

```sh
# Node runtime: Debian OS packages and npm packages.
./bin/ncsc-trivy-db benchmark image --ncsc-cache "$NCSC_CACHE" --output "$RUN/node" \
  node@sha256:28fbbb764069c698ead61d6a739a7615e8f0e07a4b8fe1473ceca70c1c3d6aaa

# Python runtime: Alpine OS packages and Python packages.
./bin/ncsc-trivy-db benchmark image --ncsc-cache "$NCSC_CACHE" --output "$RUN/python" \
  python@sha256:5049c050bdc68575a10bcb1885baa0689b6c15152d8a56a7e399fb49f783bf98
```

Open `$RUN/<target>/differences.txt` for every finding unique to one DB and
every shared finding with different severity or fix metadata. `report.json`
contains the inventories, hashes, command arguments, and full finding records.
Each output directory must be new; set a new `RUN` value for another series.

**Read the inventory line before the finding counts.** The NCSC build archives broader product records, but its scan-ready
advisory index currently covers supported OS and language package identities.
The benchmark compares what these two databases actually return through Trivy.
