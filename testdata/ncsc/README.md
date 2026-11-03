# NCSC integration fixtures

These six files are unmodified CSAF JSON downloaded from
`https://vulnerabilities.ncsc.nl/csaf/v2/<year>/<cve>.json` on 2026-10-28,
then compressed with gzip. Each retains its NCSC legal disclaimer and upstream
references. They test real product trees, statuses, version spellings, CVSS,
records without usable package identities, and byte-for-byte source preservation.

The fixtures are a small test corpus, not the full database. Network-free tests
construct a temporary mirror from them. `TestStockTrivy` additionally invokes an
installed Trivy CLI and checks affected, patched, and different-distro controls.

The `conversion/` directory contains additional source fixtures for converter
regressions, with SHA-256 expectations in `internal/csaf/`. Its
`cve-2021-28706.json.gz` was exported unchanged from the local archived NCSC
snapshot on 2026-11-10. The source URL is
https://vulnerabilities.ncsc.nl/csaf/v2/2021/cve-2021-28706.json.
It tests the union of nested `xen` ranges in Alpine 3.12 and affected, fixed,
and different-release Trivy scan controls.

`conversion/cve-2022-24439.json.gz` was exported unchanged from the local archived
NCSC snapshot on 2026-11-10. Its source URL is
https://vulnerabilities.ncsc.nl/csaf/v2/2022/cve-2022-24439.json.
It tests Python release-label case normalization while preserving the original
GitPython PURL and product observation.
