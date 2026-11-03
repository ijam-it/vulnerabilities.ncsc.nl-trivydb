// Package benchmark compares database snapshots using the same SBOM and scanner.
package benchmark

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"ncsc-trivy-db/internal/scan"
)

type Options struct {
	Kind, Target, NCSCCache, TrivyCache, Output, Platform string
	Timeout                                               time.Duration
}

type Finding struct {
	Type         string `json:"type"`
	Package      string `json:"package"`
	Version      string `json:"version"`
	PURL         string `json:"purl"`
	ID           string `json:"id"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixed_version"`
	Source       string `json:"source"`
}

type Difference struct {
	NCSC  Finding `json:"ncsc"`
	Trivy Finding `json:"trivy"`
}

type Counts struct {
	Findings   int            `json:"findings"`
	UniqueIDs  int            `json:"unique_vulnerability_ids"`
	ByType     map[string]int `json:"by_type"`
	BySeverity map[string]int `json:"by_severity"`
}

type Comparison struct {
	NCSC                Counts       `json:"ncsc"`
	Trivy               Counts       `json:"trivy"`
	Shared              []Finding    `json:"shared"` // NCSC metadata; differences below preserve both sides.
	NCSCOnly            []Finding    `json:"ncsc_only"`
	TrivyOnly           []Finding    `json:"trivy_only"`
	MetadataDifferences []Difference `json:"metadata_differences"`
}

type Database struct {
	SHA256   string          `json:"sha256"`
	Bytes    int64           `json:"bytes"`
	Metadata json.RawMessage `json:"metadata"`
	Coverage json.RawMessage `json:"coverage,omitempty"`
}

type Validation struct {
	Packages       int            `json:"package_occurrences"`
	PackagesByType map[string]int `json:"packages_by_type"`
	ImageParity    *bool          `json:"image_inventory_and_findings_match,omitempty"`
}

type SBOMInventory struct {
	Format     string         `json:"format,omitempty"`
	Components int            `json:"components"`
	ByType     map[string]int `json:"by_type,omitempty"`
	WithPURL   int            `json:"with_purl"`
	WithCPE    int            `json:"with_cpe"`
	CPEOnly    int            `json:"cpe_only"`
}

type Command struct {
	Arguments []string `json:"arguments"`
	Seconds   float64  `json:"seconds"`
}

type Report struct {
	StartedAt    time.Time             `json:"started_at"`
	FinishedAt   time.Time             `json:"finished_at"`
	Kind         string                `json:"kind"`
	Target       string                `json:"target"`
	Image        string                `json:"resolved_image,omitempty"`
	Platform     string                `json:"platform,omitempty"`
	SBOMSHA256   string                `json:"sbom_sha256"`
	TrivyVersion string                `json:"trivy_version"`
	Host         string                `json:"host"`
	Databases    map[string]Database   `json:"databases"`
	SBOM         SBOMInventory         `json:"sbom_inventory"`
	Validation   map[string]Validation `json:"validation"`
	Comparison   Comparison            `json:"comparison"`
	Commands     []Command             `json:"commands"`
}

// Only the report fields needed for comparison are decoded; complete output is saved.
type scanReport struct {
	SchemaVersion int
	Metadata      struct {
		RepoDigests []string
		OS          *struct{ Family, Name string }
	}
	Results []struct {
		Type     string
		Packages []struct {
			Name, Version, FilePath string
			Identifier              struct{ PURL string }
		}
		Vulnerabilities []struct {
			PkgName, InstalledVersion, VulnerabilityID, Severity, FixedVersion string
			PkgIdentifier                                                      struct{ PURL string }
			DataSource                                                         struct{ ID string }
		}
	}
}

func decode(raw []byte) (scanReport, error) {
	var r scanReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	if r.SchemaVersion != 2 {
		return r, fmt.Errorf("expected Trivy JSON schema 2, got %d", r.SchemaVersion)
	}
	return r, nil
}

// Summarize identifiers in the supplied inventory independently of what Trivy
// recognizes. Vendor SBOMs can contain components that stock Trivy never scans.
func summarizeSBOM(raw []byte) SBOMInventory {
	s := SBOMInventory{ByType: map[string]int{}}
	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
		Components  []struct {
			Type, PURL, CPE string
		} `json:"components"`
		Packages []struct {
			ExternalRefs []struct{ ReferenceType string } `json:"externalRefs"`
		} `json:"packages"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return s
	}
	if doc.BomFormat == "CycloneDX" {
		s.Format = "CycloneDX"
		s.Components = len(doc.Components)
		for _, c := range doc.Components {
			s.ByType[c.Type]++
			if c.PURL != "" {
				s.WithPURL++
			}
			if c.CPE != "" {
				s.WithCPE++
				if c.PURL == "" {
					s.CPEOnly++
				}
			}
		}
	} else if doc.SPDXVersion != "" {
		s.Format = "SPDX"
		s.Components = len(doc.Packages)
		for _, p := range doc.Packages {
			purl, cpe := false, false
			for _, ref := range p.ExternalRefs {
				switch strings.ToLower(ref.ReferenceType) {
				case "purl":
					purl = true
				case "cpe22type", "cpe23type":
					cpe = true
				}
			}
			if purl {
				s.WithPURL++
			}
			if cpe {
				s.WithCPE++
				if !purl {
					s.CPEOnly++
				}
			}
		}
	}
	return s
}

// Include ecosystem, PURL, version and occurrence path; a CVE count alone hides loss.
func inventory(r scanReport) map[string]int {
	m := map[string]int{}
	for _, result := range r.Results {
		for _, p := range result.Packages {
			// Trivy image JSON splits Debian Version/Release/Epoch, while SBOM
			// JSON puts the full version in Version. PURL retains the full version
			// in both, so use it as the authoritative identity when available.
			version := p.Version
			if p.Identifier.PURL != "" {
				version = ""
			}
			key := strings.Join([]string{result.Type, p.Name, version, p.Identifier.PURL, p.FilePath}, "\x00")
			m[key]++
		}
	}
	return m
}

func key(f Finding) string {
	return strings.Join([]string{f.Type, f.Package, f.Version, f.PURL, f.ID}, "\x00")
}

func findings(r scanReport) map[string]Finding {
	m := map[string]Finding{}
	for _, result := range r.Results {
		for _, v := range result.Vulnerabilities {
			severity := v.Severity
			if severity == "" {
				severity = "UNKNOWN"
			}
			f := Finding{result.Type, v.PkgName, v.InstalledVersion, v.PkgIdentifier.PURL, v.VulnerabilityID, severity, v.FixedVersion, v.DataSource.ID}
			m[key(f)] = f
		}
	}
	return m
}

func count(m map[string]Finding) Counts {
	c := Counts{Findings: len(m), ByType: map[string]int{}, BySeverity: map[string]int{}}
	ids := map[string]bool{}
	for _, f := range m {
		c.ByType[f.Type]++
		c.BySeverity[f.Severity]++
		ids[f.ID] = true
	}
	c.UniqueIDs = len(ids)
	return c
}

func compare(n, t scanReport) Comparison {
	a, b := findings(n), findings(t)
	c := Comparison{NCSC: count(a), Trivy: count(b), Shared: []Finding{}, NCSCOnly: []Finding{}, TrivyOnly: []Finding{}, MetadataDifferences: []Difference{}}
	for _, k := range sortedKeys(a) {
		f := a[k]
		if other, ok := b[k]; ok {
			c.Shared = append(c.Shared, f)
			if f.Severity != other.Severity || f.FixedVersion != other.FixedVersion {
				c.MetadataDifferences = append(c.MetadataDifferences, Difference{f, other})
			}
		} else {
			c.NCSCOnly = append(c.NCSCOnly, f)
		}
	}
	for _, k := range sortedKeys(b) {
		if _, ok := a[k]; !ok {
			c.TrivyOnly = append(c.TrivyOnly, b[k])
		}
	}
	return c
}

func sortedKeys(m map[string]Finding) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func validateParity(sbom, image scanReport) error {
	if !reflect.DeepEqual(sbom.Metadata.OS, image.Metadata.OS) {
		return fmt.Errorf("SBOM/image OS metadata differs")
	}
	if !reflect.DeepEqual(inventory(sbom), inventory(image)) {
		return fmt.Errorf("SBOM/image package inventory differs")
	}
	if !reflect.DeepEqual(findings(sbom), findings(image)) {
		return fmt.Errorf("SBOM/image findings differ")
	}
	return nil
}

func snapshot(cache string) (Database, error) {
	var d Database
	var err error
	d.Metadata, err = os.ReadFile(filepath.Join(cache, "db", "metadata.json"))
	if err != nil {
		return d, fmt.Errorf("missing database metadata in %s: %w; download/build the cache first", cache, err)
	}
	var metadata struct{ Version int }
	if err = json.Unmarshal(d.Metadata, &metadata); err != nil || metadata.Version != 2 {
		return d, fmt.Errorf("invalid schema-v2 metadata in %s", cache)
	}
	f, err := os.Open(filepath.Join(cache, "db", "trivy.db"))
	if err != nil {
		return d, err
	}
	defer f.Close()
	h := sha256.New()
	d.Bytes, err = io.Copy(h, f)
	if err != nil {
		return d, err
	}
	if d.Bytes == 0 {
		return d, fmt.Errorf("empty database in %s", cache)
	}
	d.SHA256 = hex.EncodeToString(h.Sum(nil))
	return d, nil
}

// Run never updates either database. Image pulls are needed only for image mode.
// Failed runs retain logs but never publish report.json as a successful result.
func Run(ctx context.Context, o Options, output io.Writer) (Report, error) {
	r := Report{StartedAt: time.Now().UTC(), Kind: o.Kind, Target: o.Target, Host: runtime.GOOS + "/" + runtime.GOARCH, Databases: map[string]Database{}, Validation: map[string]Validation{}}
	if o.Kind != "image" && o.Kind != "sbom" {
		return r, fmt.Errorf("benchmark kind must be image or sbom")
	}
	if o.Target == "" || o.Output == "" || o.Timeout <= 0 {
		return r, fmt.Errorf("target, --output and a positive --timeout are required")
	}
	if o.Kind == "image" && o.Platform == "" {
		return r, fmt.Errorf("image platform is required")
	}
	var err error
	o.Output, err = filepath.Abs(o.Output)
	if err != nil {
		return r, err
	}
	caches := map[string]string{"ncsc": o.NCSCCache, "trivy": o.TrivyCache}
	stats := map[string]os.FileInfo{}
	for _, name := range []string{"ncsc", "trivy"} {
		cache, err := filepath.Abs(caches[name])
		if err != nil {
			return r, err
		}
		caches[name] = cache
		info, err := os.Stat(filepath.Join(cache, "db", "trivy.db"))
		if err != nil {
			return r, fmt.Errorf("%s cache: %w; build NCSC or download the official database first", name, err)
		}
		stats[name] = info
	}
	if os.SameFile(stats["ncsc"], stats["trivy"]) {
		return r, fmt.Errorf("the two caches point to the same database")
	}
	if err = os.MkdirAll(filepath.Dir(o.Output), 0755); err != nil {
		return r, err
	}
	if err = os.Mkdir(o.Output, 0755); err != nil {
		return r, err
	}
	fmt.Fprintln(output, "Recording database snapshots...")
	for _, name := range []string{"ncsc", "trivy"} {
		d, err := snapshot(caches[name])
		if err != nil {
			return r, err
		}
		if name == "ncsc" {
			d.Coverage, err = os.ReadFile(filepath.Join(caches[name], "coverage.json"))
			if err != nil {
				return r, err
			}
			var coverage struct {
				Complete       bool
				DatabaseSHA256 string `json:"database_sha256"`
			}
			if err = json.Unmarshal(d.Coverage, &coverage); err != nil {
				return r, err
			}
			if !coverage.Complete || coverage.DatabaseSHA256 != d.SHA256 {
				return r, fmt.Errorf("NCSC build is incomplete or its checksum does not match coverage.json")
			}
		}
		r.Databases[name] = d
	}
	// Suppress project/user config and ignore rules, and isolate TRIVY_* settings.
	config := filepath.Join(o.Output, "trivy.yaml")
	ignore := filepath.Join(o.Output, ".trivyignore")
	if err = os.WriteFile(config, []byte("{}\n"), 0644); err != nil {
		return r, err
	}
	if err = os.WriteFile(ignore, nil, 0644); err != nil {
		return r, err
	}
	run := func(label string, args ...string) ([]byte, error) {
		callCtx, cancel := context.WithTimeout(ctx, o.Timeout)
		defer cancel()
		cmd := exec.CommandContext(callCtx, "trivy", args...)
		cmd.WaitDelay = 5 * time.Second
		for _, env := range os.Environ() {
			name, _, _ := strings.Cut(env, "=")
			if !strings.HasPrefix(name, "TRIVY_") || slices.Contains([]string{"TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN"}, name) {
				cmd.Env = append(cmd.Env, env)
			}
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		start := time.Now()
		raw, e := cmd.Output()
		r.Commands = append(r.Commands, Command{append([]string{"trivy"}, args...), time.Since(start).Seconds()})
		if err := os.WriteFile(filepath.Join(o.Output, label+".log"), stderr.Bytes(), 0644); err != nil {
			return nil, err
		}
		if callCtx.Err() != nil {
			return nil, callCtx.Err()
		}
		if e != nil {
			return nil, fmt.Errorf("%s: %w\n%s", label, e, stderr.String())
		}
		if strings.Contains(stderr.String(), "Version matching error") {
			return nil, fmt.Errorf("%s: Trivy could not interpret a version constraint; see log", label)
		}
		if label != "version" && label != "generated-sbom" {
			if err := writeGzip(filepath.Join(o.Output, label+".json.gz"), raw); err != nil {
				return nil, err
			}
		}
		return raw, nil
	}
	version, err := run("version", "--version")
	if err != nil {
		return r, err
	}
	r.TrivyVersion = strings.SplitN(strings.TrimSpace(string(version)), "\n", 2)[0]
	sbomPath := filepath.Join(o.Output, "sbom.cdx.json")
	if o.Kind == "image" {
		fmt.Fprintln(output, "Generating SBOM from image...")
		// CycloneDX generation without --scanners vuln does not consult either DB.
		args := []string{"image", "--config", config, "--cache-dir", caches["trivy"], "--format", "cyclonedx", "--image-src", "remote", "--platform", o.Platform, "--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update", "--offline-scan", "--skip-version-check", "--disable-telemetry", "--no-progress", "--", o.Target}
		raw, err := run("generated-sbom", args...)
		if err != nil {
			return r, err
		}
		var bom struct {
			Metadata struct {
				Component struct {
					Properties []struct{ Name, Value string }
				}
			}
		}
		if err = json.Unmarshal(raw, &bom); err != nil {
			return r, err
		}
		for _, p := range bom.Metadata.Component.Properties {
			if p.Name == "aquasecurity:trivy:RepoDigest" {
				r.Image = p.Value
				break
			}
		}
		if !strings.Contains(r.Image, "@sha256:") {
			return r, fmt.Errorf("SBOM has no resolved image digest")
		}
		if strings.Contains(o.Target, "@sha256:") && !strings.HasSuffix(r.Image, strings.SplitN(o.Target, "@", 2)[1]) {
			return r, fmt.Errorf("resolved image digest differs from requested digest")
		}
		r.Platform = o.Platform
		if err = os.WriteFile(sbomPath, raw, 0644); err != nil {
			return r, err
		}
	} else {
		raw, err := os.ReadFile(o.Target)
		if err != nil {
			return r, err
		}
		// Name is format-neutral for user-supplied CycloneDX and SPDX documents.
		sbomPath = filepath.Join(o.Output, "sbom.json")
		if err = os.WriteFile(sbomPath, raw, 0644); err != nil {
			return r, err
		}
	}
	sbomRaw, err := os.ReadFile(sbomPath)
	if err != nil {
		return r, err
	}
	r.SBOM = summarizeSBOM(sbomRaw)
	sum := sha256.Sum256(sbomRaw)
	r.SBOMSHA256 = hex.EncodeToString(sum[:])
	results := map[string]scanReport{}
	for _, name := range []string{"ncsc", "trivy"} {
		fmt.Fprintf(output, "Scanning SBOM with %s...\n", name)
		args, _ := scan.Arguments("sbom", caches[name], []string{"--config", config, "--ignorefile", ignore, "--format", "json", "--list-all-pkgs", "--", sbomPath})
		raw, err := run(name+"-sbom", args...)
		if err != nil {
			return r, err
		}
		result, err := decode(raw)
		if err != nil {
			return r, fmt.Errorf("%s: %w", name, err)
		}
		if o.Kind == "image" && len(inventory(result)) == 0 {
			return r, fmt.Errorf("%s: no packages detected in image scan", name)
		}
		results[name] = result
		for _, f := range findings(result) {
			if (name == "ncsc" && f.Source != "ncsc-nl") || (name == "trivy" && f.Source == "ncsc-nl") {
				return r, fmt.Errorf("unexpected source %q in %s cache", f.Source, name)
			}
		}
		v := Validation{PackagesByType: map[string]int{}}
		for _, rr := range result.Results {
			v.Packages += len(rr.Packages)
			v.PackagesByType[rr.Type] += len(rr.Packages)
		}
		if o.Kind == "image" {
			fmt.Fprintf(output, "Validating %s SBOM findings against pinned image...\n", name)
			args, _ = scan.Arguments("image", caches[name], []string{"--config", config, "--ignorefile", ignore, "--image-src", "remote", "--platform", o.Platform, "--format", "json", "--list-all-pkgs", "--", r.Image})
			raw, err = run(name+"-image", args...)
			if err != nil {
				return r, err
			}
			direct, err := decode(raw)
			if err != nil {
				return r, err
			}
			if !slices.Contains(direct.Metadata.RepoDigests, r.Image) {
				return r, fmt.Errorf("direct scan did not resolve the SBOM image digest")
			}
			if err = validateParity(result, direct); err != nil {
				return r, fmt.Errorf("%s validation: %w", name, err)
			}
			passed := true
			v.ImageParity = &passed
		}
		r.Validation[name] = v
	}
	if !reflect.DeepEqual(inventory(results["ncsc"]), inventory(results["trivy"])) {
		return r, fmt.Errorf("database scans produced different package inventories")
	}
	if r.Validation["ncsc"].Packages == 0 && r.SBOM.Components == 0 {
		return r, fmt.Errorf("no packages detected and no SBOM components identified; refusing an empty comparison")
	}
	// Refuse to record comparisons if another process replaced/updated a DB during the run.
	for _, name := range []string{"ncsc", "trivy"} {
		info, err := os.Stat(filepath.Join(caches[name], "db", "trivy.db"))
		if err != nil {
			return r, err
		}
		metadata, err := os.ReadFile(filepath.Join(caches[name], "db", "metadata.json"))
		if err != nil {
			return r, err
		}
		if !os.SameFile(stats[name], info) || info.Size() != stats[name].Size() || !info.ModTime().Equal(stats[name].ModTime()) || !bytes.Equal(metadata, r.Databases[name].Metadata) {
			return r, fmt.Errorf("%s database changed during benchmark", name)
		}
	}
	r.Comparison = compare(results["ncsc"], results["trivy"])
	r.FinishedAt = time.Now().UTC()
	if err = writeDifferences(filepath.Join(o.Output, "differences.txt"), r.Comparison); err != nil {
		return r, err
	}
	if err = writeJSON(filepath.Join(o.Output, "report.json"), r); err != nil {
		return r, err
	}
	printSummary(output, r)
	fmt.Fprintf(output, "Full finding lists: %s\nMachine-readable report: %s\n", filepath.Join(o.Output, "differences.txt"), filepath.Join(o.Output, "report.json"))
	return r, nil
}

func printSummary(w io.Writer, r Report) {
	fmt.Fprintf(w, "\nTarget: %s (%s)\n", r.Target, r.Kind)
	fmt.Fprintf(w, "Scanner: %s\nSBOM SHA-256: %s\n", r.TrivyVersion, r.SBOMSHA256)
	for _, name := range []string{"ncsc", "trivy"} {
		fmt.Fprintf(w, "%s DB SHA-256: %s\n", name, r.Databases[name].SHA256)
	}
	if r.SBOM.Format != "" {
		fmt.Fprintf(w, "SBOM: %s; %d components (%d PURLs, %d CPEs, %d CPE-only)\n", r.SBOM.Format, r.SBOM.Components, r.SBOM.WithPURL, r.SBOM.WithCPE, r.SBOM.CPEOnly)
	}
	packageTypes := r.Validation["trivy"].PackagesByType
	var typeNames []string
	for name := range packageTypes {
		typeNames = append(typeNames, name)
	}
	slices.Sort(typeNames)
	var typeCounts []string
	for _, name := range typeNames {
		typeCounts = append(typeCounts, fmt.Sprintf("%s %d", name, packageTypes[name]))
	}
	if len(typeCounts) > 0 {
		fmt.Fprintf(w, "Packages recognized by Trivy: %d (%s)\n", r.Validation["trivy"].Packages, strings.Join(typeCounts, ", "))
	} else {
		fmt.Fprintf(w, "Packages recognized by Trivy: %d\n", r.Validation["trivy"].Packages)
	}
	if r.Validation["trivy"].Packages == 0 {
		fmt.Fprintln(w, "No SBOM packages were recognized by Trivy. Zero findings here do not compare database coverage for these components.")
	}
	t := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(t, "\nMetric\tNCSC\tOfficial Trivy")
	fmt.Fprintf(t, "Package/version/vulnerability findings\t%d\t%d\n", r.Comparison.NCSC.Findings, r.Comparison.Trivy.Findings)
	fmt.Fprintf(t, "Unique vulnerability IDs\t%d\t%d\n", r.Comparison.NCSC.UniqueIDs, r.Comparison.Trivy.UniqueIDs)
	fmt.Fprintf(t, "Exclusive findings\t%d\t%d\n", len(r.Comparison.NCSCOnly), len(r.Comparison.TrivyOnly))
	types := map[string]bool{}
	for name := range r.Comparison.NCSC.ByType {
		types[name] = true
	}
	for name := range r.Comparison.Trivy.ByType {
		types[name] = true
	}
	var names []string
	for name := range types {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		fmt.Fprintf(t, "Findings (%s)\t%d\t%d\n", name, r.Comparison.NCSC.ByType[name], r.Comparison.Trivy.ByType[name])
	}
	t.Flush()
	fmt.Fprintf(w, "Shared findings: %d; severity/fix differences among shared findings: %d\n", len(r.Comparison.Shared), len(r.Comparison.MetadataDifferences))
	for _, group := range []struct {
		name     string
		findings []Finding
	}{{"NCSC", r.Comparison.NCSCOnly}, {"Trivy", r.Comparison.TrivyOnly}} {
		if len(group.findings) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s-only examples (up to 5; all in differences.txt):\n", group.name)
		for _, f := range group.findings[:min(5, len(group.findings))] {
			fmt.Fprintf(w, "  %s %s@%s (%s)\n", f.ID, f.Package, f.Version, f.Type)
		}
	}
	if r.Kind == "image" {
		fmt.Fprintln(w, "Validation: SBOM inventory and findings match direct image scans for both databases.")
	} else if r.Validation["trivy"].Packages == 0 {
		fmt.Fprintln(w, "Validation: SBOM components were present, but neither database was tested on a recognized package.")
	} else {
		fmt.Fprintln(w, "Validation: both databases scanned the same package inventory; original image not checked.")
	}
	if r.Validation["trivy"].Packages > 0 {
		fmt.Fprintln(w, "Counts show finding overlap for this frozen inventory and database pair.")
	}
}

func writeDifferences(path string, c Comparison) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Shared: %d | NCSC only: %d | Official Trivy only: %d | Shared metadata differences: %d\n", len(c.Shared), len(c.NCSCOnly), len(c.TrivyOnly), len(c.MetadataDifferences))
	fmt.Fprintf(&b, "\nShared findings (%d)\n", len(c.Shared))
	for _, f := range c.Shared {
		fmt.Fprintf(&b, "%s | %s | %s@%s | %s\n", f.ID, f.Type, f.Package, f.Version, f.PURL)
	}
	for _, group := range []struct {
		label    string
		findings []Finding
	}{{"NCSC only", c.NCSCOnly}, {"Official Trivy only", c.TrivyOnly}} {
		fmt.Fprintf(&b, "\n%s (%d)\n", group.label, len(group.findings))
		for _, f := range group.findings {
			fmt.Fprintf(&b, "%s | %s | %s@%s | %s\n", f.ID, f.Type, f.Package, f.Version, f.PURL)
		}
	}
	fmt.Fprintf(&b, "\nShared finding metadata differences (%d)\n", len(c.MetadataDifferences))
	for _, d := range c.MetadataDifferences {
		fmt.Fprintf(&b, "%s | %s | %s@%s | NCSC severity=%s fixed=%s | Official severity=%s fixed=%s\n", d.NCSC.ID, d.NCSC.Type, d.NCSC.Package, d.NCSC.Version, d.NCSC.Severity, d.NCSC.FixedVersion, d.Trivy.Severity, d.Trivy.FixedVersion)
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
func writeGzip(path string, b []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	g := gzip.NewWriter(f)
	if _, err = g.Write(b); err != nil {
		g.Close()
		return err
	}
	if err = g.Close(); err != nil {
		return err
	}
	return f.Close()
}
