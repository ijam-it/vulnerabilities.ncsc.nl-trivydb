# From CSAF advisories to Trivy findings

This guide describes the `conversion-v2` policy for turning NCSC CSAF data into
Trivy findings. Converter changes require a database rebuild; existing databases
retain their original policy. See [dev.md](dev.md) for development instructions.

CSAF describes vulnerabilities and affected products. Trivy needs to know whether
an installed package, at a specific version and in a specific ecosystem or OS
release, matches a CVE. The converter archives the advisory, resolves product
references to packages, translates supported statuses and versions into matching
rules, and stores those rules alongside CVE details.

## Identify packages

CSAF information must be read together:

| CSAF information | Purpose |
| --- | --- |
| Vulnerability `cve` | Identifies the CVE |
| Product tree | Supplies vendor, family, package, version or range, and sometimes platform or architecture; products can inherit parent context |
| Product identification helper | Supplies a package URL (PURL) or another identifier, such as a CPE |
| `product_id` | Connects vulnerability references to the tree; it is not a Trivy package name |
| `product_status` | Describes affected, fixed, not-affected, or other states |
| Notes, scores, references, dates | Supply vulnerability details |

Matching requires an ecosystem and package name, plus a distribution release for
OS packages. Illustrative PURL mappings:

| PURL | Trivy ecosystem or release | Package name |
| --- | --- | --- |
| `pkg:npm/Example` | `npm` | `example` |
| `pkg:pypi/Example_Lib` | `pip` | `example-lib` |
| `pkg:maven/org.example/example-lib` | `maven` | `org.example:example-lib` |
| `pkg:deb/debian/openssl?distro=bookworm` | Debian 12 | `openssl` |
| `pkg:apk/alpine/busybox?distro=3.20` | Alpine 3.20 | `busybox` |

Names follow ecosystem conventions: Maven uses group and artifact, Python names
are lowercased with underscores replaced by hyphens, and Go module paths retain case.

Without a PURL, a supported explicit scheme such as `vers:npm/...` can identify
the ecosystem if the tree supplies a package name. Specific tree mappings also
support Debian packages and Alpine source packages: vendor `Alpine`, family
`Alpine:v3.20`, and package `sqlite` identify Alpine 3.20's `sqlite`, even
with `vers:unknown/...`.

Vendor names, prose, and CPEs alone are insufficient. The converter does not
guess identities or discard restrictions: architecture-specific OS packages
and language PURLs with qualifiers or subpaths are excluded.

## Interpret statuses

Each product/status reference is evaluated separately.

| CSAF status | Matching behavior |
| --- | --- |
| `known_affected` | Creates a rule when identity and affected versions are supported |
| `first_fixed` | For supported OS packages, an exact version marks the first safe version; older versions in that release are affected. Ignored for language packages |
| `fixed` | Ignored: a fixed version need not be the first fix |
| `known_not_affected` | Ignored; does not subtract from affected ranges |
| Others, including `under_investigation`, `recommended`, `last_affected` | Ignored |

Ignored statuses remain archived. Language rules use explicit affected versions;
fixed-product observations do not populate `PatchedVersions` or `FixedVersion`.

## Translate versions

VERS expressions combine a scheme with affected versions, such as
`vers:npm/>=1.2.0|<2.0.0`. Ordering follows the ecosystem, including distribution
revisions such as Alpine's `-r1` and `-r10`. An explicit PURL version takes
precedence over a tree range.

### Language packages

Rules populate `VulnerableVersions`: list items are alternatives (**OR**), while
comma-separated conditions within an item must all hold (**AND**).

| Source range for an identified npm package | Trivy `VulnerableVersions` |
| --- | --- |
| `vers:npm/1.2.0` | `["= 1.2.0"]` |
| `vers:npm/>=1.2.0\|<2.0.0` | `[">= 1.2.0, < 2.0.0"]` |
| `vers:npm/<1.0.0\|>2.0.0` | `["< 1.0.0", "> 2.0.0"]` |
| `vers:npm/>=1.0.0\|!=1.2.0\|<2.0.0` | `[">= 1.0.0, < 1.2.0", "> 1.2.0, < 2.0.0"]` |

The meaning of `|` depends on surrounding operators. Invalid or unsupported
ranges are excluded rather than broadened. Python constraints are lowercased
before Trivy parser validation: PURL version `0.3.2.RC1` becomes
`== 0.3.2.rc1`, while the original PURL and range remain preserved.

For example, an illustrative `CVE-2026-1234` referencing `product-1` as
`known_affected`, with PURL `pkg:npm/example-lib` and range
`vers:npm/>=1.2.0|<2.0.0`, becomes:

```text
Source:    NCSC Netherlands CSAF
Ecosystem: npm
Package:   example-lib
CVE:       CVE-2026-1234
Affected:  >= 1.2.0 AND < 2.0.0
```

Installed version `1.5.0` matches; `1.1.0` and `2.0.0` do not. The upper bound
does not populate a language package's fixed-version field.

Supported ranges for the same CVE, package, and ecosystem are combined into one
advisory. Different packages or OS releases receive separate advisories, so one
CVE can produce many rules.

### OS packages

Debian, Ubuntu, and Alpine use Trivy's OS advisory fields. A range
`< fixed-version` or an exact `first_fixed` observation can supply `FixedVersion`.
Alpine also supports an inclusive lower boundary in `AffectedVersion`.

The frozen [CVE-2025-29087 fixture](testdata/ncsc/conversion/cve-2025-29087.json.gz)
describes Alpine 3.20's `sqlite` as `known_affected` with
`vers:unknown/>=3.44.0|<3.45.3-r2`. This produces
`AffectedVersion = 3.44.0` and `FixedVersion = 3.45.3-r2`. Older versions, the
fixed version, and other releases fall outside this rule.

The OS format excludes unrepresentable ranges, including bounded Debian
intervals, exact affected OS versions alone, and Alpine intervals with holes.
Observations merge independently of input order when their union forms one
supported interval: contained, overlapping, and touching ranges can merge.
Gaps or conflicting first-fix boundaries produce `os_affected_range_conflict`.
An explicit all-version range `*` takes precedence over narrower observations.

For example, [CVE-2021-28706](https://vulnerabilities.ncsc.nl/csaf/v2/2021/cve-2021-28706.json)
lists these affected ranges for Alpine 3.12's `xen`:

```text
>=0   and <4.13.4-r3
>=0   and <4.13.4-r2
>=3.2 and <4.13.4-r2
```

Their union is the first range, yielding `AffectedVersion = 0` and
`FixedVersion = 4.13.4-r3`. By contrast, `>=1|<2` and `>=3|<4` cannot merge:
doing so would incorrectly include versions from `2` up to `3`.

## Separate uncertainty from matching

Each product/status reference has one outcome:

| Outcome | Meaning | Trivy matching rule? |
| --- | --- | --- |
| Supported | Identity, status, and versions can be represented | Yes, possibly combined with other references |
| Uncertain candidate | Supported package with `known_affected`, but versions explicitly end in `/unknown` | No |
| Excluded | Missing, unsupported, invalid, or unrepresentable information | No |
| Ignored | Status is not used for matching | No |

The frozen [CVE-2022-0563 fixture](testdata/ncsc/conversion/cve-2022-0563.json.gz)
identifies Debian bookworm's `util-linux` with `vers:deb/unknown`. It becomes a
Debian 12 candidate with reason `affected_versions_unspecified`, without claiming
every version is affected. Explicit `unknown` and `*` have different meanings.

A CVE can have several outcomes across its references. Coverage counts refer to
product/status references, not unique CVEs. Complete source ingestion therefore
does not imply complete matching coverage.

## Preserve details and evidence

CVE details are stored separately, including for CVEs without usable rules.

| CSAF data | Database field or use |
| --- | --- |
| CVE and vulnerability title | Vulnerability ID and `Title` |
| Description or summary notes | Deduplicated, combined `Description` |
| CWE ID | `CweIDs` |
| Vulnerability reference URLs and original NCSC URL | Deduplicated `References` |
| CVSS scores and vectors | Source-labelled `CVSS` and derived severity |
| Valid vulnerability `release_date` | `PublishedDate` |
| Valid tracking `current_release_date` | `LastModifiedDate` |
| EPSS and NCSC Score notes | Custom metadata |
| Source document, product IDs, original ranges, conversion rules | Traceability metadata for supported rules |

Severity prefers CVSS v4, then v3, then v2. The highest structured base score
within each generation is retained; specially titled NCSC notes can also supply
v4 scores and vectors. Severity is low below 4, medium from 4, high from 7, and
critical from 9; zero or missing scores mean unknown, and v2 is capped at high.
Scores do not affect matching. The document's initial publication date does not
substitute for the vulnerability's publication date.

Original CSAF JSON is preserved byte for byte, compressed in the database.
Source URLs and SHA-256 hashes link records to this evidence, including content
outside the converted fields.

## Inspect the result

The build produces `db/trivy.db` and metadata in standard Trivy format, containing
CVE details, rules grouped by ecosystem or OS release, `NCSC Netherlands CSAF`
attribution, archived documents, conversion policy, and separate candidates.

During image or SBOM scans, Trivy compares installed packages and versions
against supported rules, linking matches to CVE details. A description or
candidate alone cannot produce a finding. A clean scan means no supported rule
matched, not that every archived advisory was checked against the inventory.

For a database built at the default location:

```sh
./bin/ncsc-trivy-db coverage --cache dist/ncsc
./bin/ncsc-trivy-db coverage --cache dist/ncsc --cve CVE-2025-29087 --format json
./bin/ncsc-trivy-db export-csaf --db dist/ncsc/db/trivy.db 2025/cve-2025-29087.json
```

`coverage.json` records outcome counts; `unmapped-products.ndjson.gz` lists
excluded references and reasons. Use `coverage --cve CVE-YYYY-NNNN` to inspect
individual decisions in your snapshot.

## Examples of exclusions reported by coverage

These illustrate selected **Excluded product references** reasons. Counts and
source contents can vary by snapshot. Exclusions retain their source, and other
references may still make the same CVE matchable. Recovery requires passing all
remaining conversion checks and does not necessarily add a newly matchable CVE.

### `unsupported_version_range`

The version expression cannot be parsed safely for the identified ecosystem.
Two `known_affected` Python products illustrate this:

| Source | Product ID | PURL | Range |
| --- | --- | --- | --- |
| [CVE-2022-45907](https://vulnerabilities.ncsc.nl/csaf/v2/2022/cve-2022-45907.json) | `CSAFPID-3448856` | `pkg:pypi/torch@ciflow/periodic/054a2fd` | `vers:unknown/ciflow/periodic/054a2fd` |
| [CVE-2017-8342](https://vulnerabilities.ncsc.nl/csaf/v2/2017/cve-2017-8342.json) | `CSAFPID-8266288` | `pkg:pypi/radicale@archive/1.0.x` | `vers:unknown/archive/1.0.x` |

These look like repository tags or branches, not Python release versions.
Support requires verified release mappings or inventory and matching support for
the repository references. Removing prefixes, accepting slashes, or treating
`1.0.x` as every `1.0` release does not establish the affected set. Both CVEs
already have supported rules from other references.

### `invalid_version_range_sequence`

Values parse and increase, but operators form an invalid VERS sequence. A bare
version means **exactly that version**, not a lower boundary. Ignoring `!=`
exclusions, an exact version followed by an upper bound is invalid, as are
consecutive lower bounds such as `>=1.0|>=2.0`. See the
[VERS validation rules](https://github.com/package-url/vers-spec/blob/main/docs/specification/standard/specification.md#normalized-canonical-representation-and-validation).
Reversed or duplicate values instead produce `invalid_version_range_order`.

The complete local snapshot built on 10 November 2026 contained **413 references
across 84 CVEs**: 412 Alpine ranges of the form `vers:unknown/0|<FIXED_VERSION`,
and one NuGet range, `vers:nuget/2.0.0|<3.0.0`. Examples, both `known_affected`:

| Source | Product ID | Package context | Range |
| --- | --- | --- | --- |
| [CVE-2022-2200](https://vulnerabilities.ncsc.nl/csaf/v2/2022/cve-2022-2200.json) | `CSAFPID-9998948` | Alpine, `Alpine:v3.17`, `thunderbird` | `vers:unknown/0\|<102.1.0-r0` |
| [CVE-2024-12251](https://vulnerabilities.ncsc.nl/csaf/v2/2024/cve-2024-12251.json) | `CSAFPID-6766708` | `telerik ui for winui` | `vers:nuget/2.0.0\|<3.0.0` |

The Alpine expression resembles `>=0|<102.1.0-r0`, which is supported with lower
boundary `0` and fixed boundary `102.1.0-r0`, but the converter does not insert
the missing `>=`. [Telerik's advisory](https://www.telerik.com/winui/documentation/security/kb-security-command-injection-cve-2024-12251)
lists affected versions `2.0.0` through `2.11.0` and fix `3.0.0`, supporting
an intended interval `>=2.0.0|<3.0.0`; the supplied malformed range is still excluded.

Recovery requires corrected upstream ranges or a verified explicit conversion
rule recording the original expression and its interpretation. Relaxing
validation alone does not establish affected versions.

### `unsupported_purl_type`

The PURL parses, but its type or distribution has no importer mapping. This
precedes version checks; malformed PURLs instead produce `invalid_purl`.

In the complete local snapshot built on 10 November 2026, all **530 references
across 16 CVEs** with this reason used `pkg:opam/...`. OPAM is OCaml's package manager; examples
include `ocaml`, `tls`, `cstruct`, and `mirage-crypto` packages.

[CVE-2017-9772](https://vulnerabilities.ncsc.nl/csaf/v2/2017/cve-2017-9772.json)
contains `known_affected` product `CSAFPID-377820`, PURL
`pkg:opam/ocaml@4.04.0`, and range `vers:unknown/4.04.0`. Its identity is
explicit, but OPAM has no supported ecosystem mapping.

[Trivy 0.74.0's library detector](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/detector/library/driver.go)
also lacks an OPAM detector. Stock Trivy support requires package recognition,
advisory lookup, and OPAM version comparison, followed by importer support and
a database rebuild. A separate OPAM matcher using retained data is another
option. Changing PURL spelling or adding database records alone cannot supply
that support; 530 exclusions do not guarantee 530 recoverable matches.
