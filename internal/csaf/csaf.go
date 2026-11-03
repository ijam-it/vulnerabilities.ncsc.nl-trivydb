// Package csaf extracts only explicit package identities and affected versions.
// The original CSAF is retained separately; fields not modeled here are not lost.
package csaf

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

const SourceID = "ncsc-nl"
const SourceName = "NCSC Netherlands CSAF"
const PolicyVersion = "conversion-v2"

type Document struct {
	Document struct {
		CSAFVersion string `json:"csaf_version"`
		Title       string `json:"title"`
		Tracking    struct {
			ID                 string `json:"id"`
			InitialReleaseDate string `json:"initial_release_date"`
			CurrentReleaseDate string `json:"current_release_date"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree struct {
		Branches         []Branch  `json:"branches"`
		FullProductNames []Product `json:"full_product_names"`
		Relationships    []struct {
			FullProductName Product `json:"full_product_name"`
		} `json:"relationships"`
	} `json:"product_tree"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
type Branch struct {
	Category string   `json:"category"`
	Name     string   `json:"name"`
	Product  *Product `json:"product"`
	Branches []Branch `json:"branches"`
}
type Product struct {
	Name   string `json:"name"`
	ID     string `json:"product_id"`
	Helper struct {
		PURL string `json:"purl"`
		CPE  string `json:"cpe"`
	} `json:"product_identification_helper"`
	PackageName string `json:"-"`
	Version     string `json:"-"`
	Vendor      string `json:"-"`
	Family      string `json:"-"`
	Scope       string `json:"scope,omitempty"`
}
type Note struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title"`
}
type Vulnerability struct {
	CVE   string `json:"cve"`
	Title string `json:"title"`
	CWE   struct {
		ID string `json:"id"`
	} `json:"cwe"`
	Notes         []Note              `json:"notes"`
	ProductStatus map[string][]string `json:"product_status"`
	References    []struct {
		URL string `json:"url"`
	} `json:"references"`
	Scores        []map[string]json.RawMessage `json:"scores"`
	ReleaseDate   string                       `json:"release_date"`
	DiscoveryDate string                       `json:"discovery_date"`
}
type Identity struct{ Ecosystem, Package, Release, Version string }
type Advisory struct {
	AffectedVersion    string         `json:",omitempty"`
	VulnerableVersions []string       `json:",omitempty"`
	PatchedVersions    []string       `json:",omitempty"`
	FixedVersion       string         `json:",omitempty"`
	Status             int            `json:",omitempty"`
	Custom             map[string]any `json:",omitempty"`
}
type Entry struct {
	Bucket, Package, ID string
	Advisory            Advisory
}
type Unmapped struct {
	CVE           string   `json:"cve"`
	ProductID     string   `json:"product_id"`
	Status        string   `json:"status"`
	Reason        string   `json:"reason"`
	Product       Product  `json:"product"`
	OriginalRange string   `json:"original_range,omitempty"`
	RuleID        string   `json:"rule_id,omitempty"`
	Identity      Identity `json:"identity"`
}
type Candidate struct {
	CVE, ProductID, Status, OriginalRange, RuleID, Bucket, Package string
	Identity                                                       Identity
	Reason                                                         string
	IdentityEvidence                                               string
	Scope                                                          string
	SourcePath                                                     string
	CSAFSHA256                                                     string
}

func (d Document) Products() map[string]Product {
	out := map[string]Product{}
	var walk func([]Branch, Product)
	walk = func(bs []Branch, ctx Product) {
		for _, b := range bs {
			next := ctx
			switch b.Category {
			case "vendor":
				next.Vendor = b.Name
			case "product_name":
				next.PackageName = b.Name
			case "product_family":
				next.Family = b.Name
			case "product_version", "product_version_range":
				next.Version = b.Name
			case "architecture", "platform":
				next.Scope = b.Category + ":" + b.Name
			}
			if b.Product != nil {
				p := *b.Product
				p.PackageName = next.PackageName
				p.Version = next.Version
				p.Vendor = next.Vendor
				p.Family = next.Family
				p.Scope = next.Scope
				if p.Version == "" && strings.HasPrefix(p.Name, "vers:") {
					p.Version = p.Name
				}
				out[p.ID] = p
			}
			walk(b.Branches, next)
		}
	}
	walk(d.ProductTree.Branches, Product{})
	for _, p := range d.ProductTree.FullProductNames {
		if strings.HasPrefix(p.Name, "vers:") {
			p.Version = p.Name
		}
		out[p.ID] = p
	}
	for _, r := range d.ProductTree.Relationships {
		out[r.FullProductName.ID] = r.FullProductName
	}
	return out
}

var languageTypes = map[string]string{"npm": "npm", "pypi": "pip", "maven": "maven", "golang": "go", "gem": "rubygems", "cargo": "cargo", "composer": "composer", "nuget": "nuget", "hex": "erlang", "pub": "pub", "cocoapods": "cocoapods", "swift": "swift", "conan": "conan"}
var debianReleases = map[string]string{"woody": "3", "sarge": "3", "etch": "4", "lenny": "5", "squeeze": "6", "wheezy": "7", "jessie": "8", "stretch": "9", "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
var ubuntuReleases = map[string]string{"xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04", "oracular": "24.10", "plucky": "25.04", "questing": "25.10", "resolute": "26.04"}
var releaseNumber = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?$`)
var alpineRelease = regexp.MustCompile(`^([0-9]+\.[0-9]+)(?:\.[0-9]+)*$`)

func Normalize(eco, name string) string {
	switch eco {
	case "go", "cocoapods", "alpine":
		return name
	case "pip":
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	case "swift":
		return strings.TrimSuffix(strings.TrimPrefix(name, "https://"), ".git")
	default:
		return strings.ToLower(name)
	}
}

func Identify(p Product) (Identity, string) {
	if p.Scope != "" {
		return Identity{}, "os_scope_not_supported"
	}
	if p.Helper.PURL != "" {
		pu, err := packageurl.FromString(p.Helper.PURL)
		if err != nil {
			return Identity{}, "invalid_purl"
		}
		name := pu.Name
		if pu.Namespace != "" {
			name = pu.Namespace + "/" + name
		}
		// packageurl-go lowercases Go paths, while Trivy's Go lookup is case-sensitive.
		// Recover the already-validated path with its source spelling.
		if pu.Type == "golang" {
			original, _, _ := strings.Cut(strings.TrimPrefix(p.Helper.PURL, "pkg:golang/"), "?")
			original, _, _ = strings.Cut(original, "#")
			if at := strings.LastIndex(original, "@"); at >= 0 {
				original = original[:at]
			}
			if decoded, err := url.PathUnescape(original); err == nil {
				name = decoded
			}
		}
		if eco, ok := languageTypes[pu.Type]; ok {
			if pu.Type == "maven" {
				if pu.Namespace == "" {
					return Identity{}, "maven_without_group"
				}
				name = pu.Namespace + ":" + pu.Name
			}
			if len(pu.Qualifiers) > 0 || pu.Subpath != "" {
				return Identity{}, "qualified_language_purl"
			}
			return Identity{Ecosystem: eco, Package: Normalize(eco, name), Version: pu.Version}, ""
		}
		if pu.Type == "deb" && (pu.Namespace == "debian" || pu.Namespace == "ubuntu") {
			qualifiers := pu.Qualifiers.Map()
			if pu.Subpath != "" || len(qualifiers) > 2 {
				return Identity{}, "os_scope_not_supported"
			}
			for key := range qualifiers {
				if key != "arch" && key != "distro" {
					return Identity{}, "os_scope_not_supported"
				}
			}
			arch := qualifiers["arch"]
			if arch != "" && arch != "source" && arch != "src" {
				return Identity{}, "os_architecture_scope_not_supported"
			}
			distro := qualifiers["distro"]
			if distro == "" {
				return Identity{}, "os_purl_without_distro"
			}
			release := osRelease(pu.Namespace, distro)
			if release == "" {
				return Identity{}, "unsupported_os_release"
			}
			return Identity{Ecosystem: pu.Namespace, Package: Normalize(pu.Namespace, pu.Name), Release: release, Version: pu.Version}, ""
		}
		if pu.Type == "apk" && pu.Namespace == "alpine" {
			q := pu.Qualifiers.Map()
			if pu.Subpath != "" || len(q) > 2 {
				return Identity{}, "os_scope_not_supported"
			}
			for key := range q {
				if key != "distro" && key != "arch" {
					return Identity{}, "os_scope_not_supported"
				}
			}
			if q["arch"] != "" && q["arch"] != "source" && q["arch"] != "src" {
				return Identity{}, "os_architecture_scope_not_supported"
			}
			distro := q["distro"]
			if distro == "" && p.Vendor == "Alpine" {
				distro = p.Family
			}
			if distro == "" {
				return Identity{}, "os_purl_without_distro"
			}
			if p.PackageName != "" && p.PackageName != pu.Name {
				return Identity{}, "os_package_identity_conflict"
			}
			if r := osRelease("alpine", distro); r != "" {
				return Identity{Ecosystem: "alpine", Package: pu.Name, Release: r, Version: pu.Version}, ""
			}
			return Identity{}, "unsupported_os_release"
		}
		return Identity{}, "unsupported_purl_type"
	}
	// An explicit VERS ecosystem identifies a language package without guessing from vendor/CPE text.
	if strings.HasPrefix(p.Version, "vers:") && p.PackageName != "" {
		scheme, _, _ := strings.Cut(strings.TrimPrefix(p.Version, "vers:"), "/")
		if eco, ok := languageTypes[scheme]; ok {
			if eco == "maven" && !strings.Contains(p.PackageName, ":") {
				return Identity{}, "maven_without_group"
			}
			return Identity{Ecosystem: eco, Package: Normalize(eco, p.PackageName)}, ""
		}
		if scheme == "deb" && strings.EqualFold(p.Vendor, "Debian") {
			if r := osRelease("debian", p.Family); r != "" {
				return Identity{Ecosystem: "debian", Package: Normalize("debian", p.PackageName), Release: r}, ""
			}
		}
		if scheme == "unknown" && p.Vendor == "Alpine" && p.PackageName != "" {
			if r := osRelease("alpine", p.Family); r != "" {
				return Identity{Ecosystem: "alpine", Package: p.PackageName, Release: r}, ""
			}
			return Identity{}, "unsupported_os_release"
		}
	}
	if p.Helper.CPE != "" {
		return Identity{}, "cpe_without_package_identity"
	}
	return Identity{}, "no_supported_package_identity"
}
func osRelease(eco, distro string) string {
	distro = strings.ToLower(distro)
	if eco == "alpine" {
		distro = strings.TrimPrefix(distro, "alpine:")
		distro = strings.TrimPrefix(distro, "alpine-")
		distro = strings.TrimPrefix(distro, "v")
		if match := alpineRelease.FindStringSubmatch(distro); match != nil {
			return match[1]
		}
		return ""
	}
	distro = strings.TrimPrefix(distro, eco+"-")
	distro = strings.TrimPrefix(distro, eco+" ")
	if eco == "debian" {
		if r, ok := debianReleases[distro]; ok {
			return r
		}
	} else {
		if r, ok := ubuntuReleases[distro]; ok {
			return r
		}
	}
	if releaseNumber.MatchString(distro) {
		if eco == "debian" {
			r, _, _ := strings.Cut(distro, ".")
			return r
		}
		return distro
	}
	return ""
}

// Constraints translates VERS unions, intervals, points, and exclusions into
// the disjunction of conjunctions consumed by Trivy.
var versionToken = regexp.MustCompile(`^v?[0-9][0-9A-Za-z.!+_~:\-]*$`)

func Constraints(p Product, id Identity) ([]string, string) {
	equal := "= "
	if id.Ecosystem == "pip" {
		equal = "== "
	}
	exact := func(v string) ([]string, string) {
		if !versionToken.MatchString(v) {
			return nil, "unsupported_version"
		}
		return []string{equal + strings.TrimPrefix(v, "v")}, ""
	}
	if id.Version != "" && id.Version != "*" {
		return exact(id.Version)
	}
	r := p.Version
	if r == "" {
		r = p.Name
	}
	if strings.HasPrefix(r, "vers:") {
		var scheme string
		scheme, r, _ = strings.Cut(strings.TrimPrefix(r, "vers:"), "/")
		if id.Ecosystem != "" && scheme != "unknown" && scheme != "all" {
			compatible := languageTypes[scheme] == id.Ecosystem
			if scheme == "deb" && (id.Ecosystem == "debian" || id.Ecosystem == "ubuntu") {
				compatible = true
			}
			if !compatible {
				return nil, "version_scheme_mismatch"
			}
		}
		// An explicit unknown range is evidence of affected package identity,
		// not evidence that every installed version is vulnerable.
		if r == "unknown" {
			return nil, "affected_versions_unspecified"
		}
	} else if !versionToken.MatchString(r) {
		return nil, "unknown_version"
	}
	return parseRange(r, id.Ecosystem)
}

func Entries(v Vulnerability, products map[string]Product) ([]Entry, []Unmapped) {
	entries, _, unmapped := Convert(v, products)
	return entries, unmapped
}

// Convert produces version-scoped advisories and separately indexed uncertain
// observations. Unspecified affected versions never produce scan advisories.
func Convert(v Vulnerability, products map[string]Product) ([]Entry, []Candidate, []Unmapped) {
	grouped := map[string]*Entry{}
	osRanges := map[string]*osRangeSet{}
	var candidates []Candidate
	var unmapped []Unmapped
	// first_fixed is the explicit earliest safe OS version. Fixed-only observations
	// cannot be assumed to be the first fix, so they do not create OS advisories.
	for _, status := range []string{"known_affected", "first_fixed"} {
		for _, pid := range v.ProductStatus[status] {
			p, exists := products[pid]
			id, reason := Identify(p)
			if !exists {
				reason = "missing_product_reference"
			}
			osPkg := id.Ecosystem == "debian" || id.Ecosystem == "ubuntu" || id.Ecosystem == "alpine"
			if status == "first_fixed" && !osPkg {
				continue
			}
			var constraints []string
			if reason == "" {
				constraints, reason = Constraints(p, id)
			}
			bucket := id.Ecosystem + "::" + SourceName
			if osPkg {
				bucket = id.Ecosystem + " " + id.Release
			}
			if reason == "affected_versions_unspecified" && status == "known_affected" {
				candidates = append(candidates, Candidate{CVE: v.CVE, ProductID: pid, Status: status, OriginalRange: originalRange(p), RuleID: "affected-versions-unspecified-v1", Bucket: bucket, Package: id.Package, Identity: id, Reason: reason, IdentityEvidence: identityEvidence(p), Scope: p.Scope})
				continue
			}
			if reason == "" && !osPkg {
				if id.Ecosystem == "pip" {
					// PEP 440 versions are case-insensitive, but the specifier
					// parser rejects uppercase release labels such as RC.
					for i := range constraints {
						constraints[i] = strings.ToLower(constraints[i])
					}
				}
				if err := validateConstraints(id.Ecosystem, constraints); err != nil {
					reason = "trivy_cannot_parse_version_constraint"
				}
			}
			fixed := ""
			affected := ""
			allAffected := false
			if reason == "" && osPkg {
				if len(constraints) == 1 {
					switch {
					case status == "first_fixed" && strings.HasPrefix(constraints[0], "= "):
						fixed = strings.TrimPrefix(constraints[0], "= ")
					case status == "known_affected" && constraints[0] == "":
						allAffected = true
					case status == "known_affected" && strings.HasPrefix(constraints[0], "< ") && !strings.Contains(constraints[0], ","):
						fixed = strings.TrimPrefix(constraints[0], "< ")
					case id.Ecosystem == "alpine" && status == "known_affected" && strings.HasPrefix(constraints[0], ">= 0, < "):
						// Retain even the zero lower bound. Stock Trivy checks APK
						// AffectedVersion before its fixed cutoff.
						affected, fixed = "0", strings.TrimPrefix(constraints[0], ">= 0, < ")
					case id.Ecosystem == "alpine" && status == "known_affected" && strings.HasPrefix(constraints[0], ">= ") && strings.Contains(constraints[0], ", < "):
						lower, upper, _ := strings.Cut(strings.TrimPrefix(constraints[0], ">= "), ", < ")
						affected, fixed = lower, upper
					default:
						reason = "os_affected_range_not_supported_by_stock_trivy"
					}
				} else {
					reason = "os_affected_range_not_supported_by_stock_trivy"
				}
				if reason == "" && fixed != "" {
					if e := validateConstraints(id.Ecosystem, []string{"= " + fixed}); e != nil {
						reason = "trivy_cannot_parse_version_constraint"
					}
					if affected != "" {
						if e := validateConstraints(id.Ecosystem, []string{"= " + affected}); e != nil {
							reason = "trivy_cannot_parse_version_constraint"
						}
					}
				}
			}
			if reason != "" {
				unmapped = append(unmapped, Unmapped{CVE: v.CVE, ProductID: pid, Status: status, Reason: reason, Product: p, OriginalRange: originalRange(p), RuleID: "excluded-" + reason + "-v1", Identity: id})
				continue
			}
			key := bucket + "\x00" + id.Package
			e, ok := grouped[key]
			if !ok {
				e = &Entry{Bucket: bucket, Package: id.Package, ID: v.CVE, Advisory: Advisory{Custom: map[string]any{"NCSCProductIDs": []string{}, "NCSCObservations": []map[string]string{}, "NCSCSource": "https://vulnerabilities.ncsc.nl/csaf/", "NCSCPolicyVersion": PolicyVersion, "NCSCOutcome": "supported"}}}
				grouped[key] = e
			}
			e.Advisory.Custom["NCSCProductIDs"] = append(e.Advisory.Custom["NCSCProductIDs"].([]string), pid)
			rule := "language-vers-v1"
			if osPkg {
				rule = id.Ecosystem + "-cutoff-v1"
			}
			e.Advisory.Custom["NCSCObservations"] = append(e.Advisory.Custom["NCSCObservations"].([]map[string]string), map[string]string{"product_id": pid, "status": status, "range": originalRange(p), "rule_id": rule, "identity_evidence": identityEvidence(p), "release": id.Release, "scope": p.Scope})
			if osPkg {
				ranges := osRanges[key]
				if ranges == nil {
					ranges = &osRangeSet{ecosystem: id.Ecosystem}
					osRanges[key] = ranges
				}
				if allAffected {
					ranges.allAffected = true
				} else if status == "first_fixed" {
					ranges.firstFixed = append(ranges.firstFixed, fixed)
				} else {
					ranges.affected = append(ranges.affected, osRange{lower: affected, upper: fixed})
				}
			} else {
				e.Advisory.VulnerableVersions = append(e.Advisory.VulnerableVersions, constraints...)
			}
		}
	}
	var entries []Entry
	for _, e := range grouped {
		conflict := false
		if ranges := osRanges[e.Bucket+"\x00"+e.Package]; ranges != nil {
			merged, ok := ranges.merge()
			conflict = !ok
			e.Advisory.AffectedVersion, e.Advisory.FixedVersion = merged.lower, merged.upper
			e.Advisory.Status = 3
			if ranges.allAffected {
				e.Advisory.Custom["NCSCAllVersionsAffected"] = true
				e.Advisory.Status = 2
			}
		}
		if conflict {
			for _, obs := range e.Advisory.Custom["NCSCObservations"].([]map[string]string) {
				pid := obs["product_id"]
				unmapped = append(unmapped, Unmapped{CVE: v.CVE, ProductID: pid, Status: obs["status"], Reason: "os_affected_range_conflict", Product: products[pid], OriginalRange: obs["range"], RuleID: "excluded-os_affected_range_conflict-v1"})
			}
			delete(grouped, e.Bucket+"\x00"+e.Package)
			continue
		}
		e.Advisory.VulnerableVersions = Unique(e.Advisory.VulnerableVersions)
		entries = append(entries, *e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Bucket != entries[j].Bucket {
			return entries[i].Bucket < entries[j].Bucket
		}
		return entries[i].Package < entries[j].Package
	})
	return entries, candidates, unmapped
}

func originalRange(p Product) string {
	if p.Version != "" {
		return p.Version
	}
	return p.Name
}

func identityEvidence(p Product) string {
	if p.Helper.PURL != "" {
		return "purl:" + p.Helper.PURL
	}
	if p.Version != "" {
		return "product-tree:" + p.Vendor + "/" + p.Family + "/" + p.PackageName
	}
	return "product-name:" + p.Name
}

func Unique(s []string) []string {
	sort.Strings(s)
	var out []string
	for _, v := range s {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}

func Decode(raw []byte) (Document, error) {
	var d Document
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, err
	}
	if d.Document.CSAFVersion != "2.0" || len(d.Vulnerabilities) == 0 {
		return d, fmt.Errorf("unsupported or empty CSAF document")
	}
	return d, nil
}
