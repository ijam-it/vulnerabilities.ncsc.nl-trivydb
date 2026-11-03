// Package coverage explains matching coverage using the built database and its
// archived source. It never loads the global unmapped-products export.
package coverage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	bolt "go.etcd.io/bbolt"
	"ncsc-trivy-db/internal/build"
	"ncsc-trivy-db/internal/csaf"
	"ncsc-trivy-db/internal/mirror"
)

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

func CVE(value string) (string, error) {
	value = strings.ToUpper(value)
	if !cvePattern.MatchString(value) {
		return "", fmt.Errorf("invalid CVE %q; expected CVE-YYYY-NNNN", value)
	}
	return value, nil
}

type Summary struct {
	CVEs                int            `json:"cves"`
	WithMatches         int            `json:"with_matches"`
	WithoutMatches      int            `json:"without_matches"`
	Advisories          int            `json:"advisories"`
	SourceComplete      bool           `json:"source_complete"`
	SourceIndexed       int            `json:"source_indexed"`
	ReasonsAvailable    bool           `json:"reasons_available"`
	ExcludedProducts    int            `json:"excluded_product_references"`
	Reasons             map[string]int `json:"reasons"`
	PolicyVersion       string         `json:"policy_version"`
	UncertainCandidates int            `json:"uncertain_candidates"`
}

type Product struct {
	ID          string          `json:"id"`
	Status      string          `json:"source_status"`
	Outcome     string          `json:"outcome"`
	Reason      string          `json:"reason,omitempty"`
	Explanation string          `json:"explanation,omitempty"`
	Source      csaf.Product    `json:"source"`
	PackageName string          `json:"package,omitempty"`
	Version     string          `json:"version,omitempty"`
	Vendor      string          `json:"vendor,omitempty"`
	Family      string          `json:"family,omitempty"`
	Candidate   *csaf.Candidate `json:"candidate,omitempty"`
}

type Detail struct {
	CVE             string         `json:"cve"`
	Title           string         `json:"title"`
	Source          string         `json:"source"`
	Advisories      int            `json:"advisories"`
	Matched         int            `json:"matched_product_references"`
	Excluded        int            `json:"excluded_product_references"`
	Ignored         int            `json:"ignored_product_references"`
	Reasons         map[string]int `json:"reasons"`
	Products        []Product      `json:"products"`
	Uncertain       int            `json:"uncertain_product_references"`
	PolicyVersion   string         `json:"policy_version"`
	PolicyAvailable bool           `json:"policy_available"`
}

type Row struct {
	CVE        string         `json:"cve"`
	Advisories int            `json:"advisories"`
	Excluded   int            `json:"excluded_product_references"`
	Uncertain  int            `json:"uncertain_product_references"`
	Ignored    int            `json:"ignored_product_references"`
	Reasons    map[string]int `json:"reasons"`
}

type Page struct {
	Rows      []Row  `json:"cves"`
	NextAfter string `json:"next_after,omitempty"`
}

type Reader struct {
	db    *bolt.DB
	cache string
}

func Open(cache string) (*Reader, error) {
	db, err := mirror.Open(filepath.Join(cache, "db", "trivy.db"), true)
	if err != nil {
		return nil, err
	}
	r := &Reader{db: db, cache: cache}
	err = db.View(func(tx *bolt.Tx) error {
		for _, name := range []string{"vulnerability", "ncsc-csaf", "data-source", "ncsc-metadata"} {
			if tx.Bucket([]byte(name)) == nil {
				return fmt.Errorf("missing NCSC database bucket: %s", name)
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return r, nil
}

func (r *Reader) Close() error { return r.db.Close() }

// inventory reads the small matching index, never the archived document corpus.
func inventory(ctx context.Context, tx *bolt.Tx) (map[string]int, int, error) {
	counts := map[string]int{}
	total := 0
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	err := tx.Bucket([]byte("data-source")).ForEach(func(name, _ []byte) error {
		b := tx.Bucket(name)
		if b == nil {
			return fmt.Errorf("missing advisory bucket: %s", name)
		}
		return b.ForEach(func(pkg, value []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			child := b.Bucket(pkg)
			if child == nil {
				return fmt.Errorf("invalid package bucket: %s/%s", name, pkg)
			}
			return child.ForEach(func(cve, value []byte) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				counts[string(cve)]++
				total++
				return nil
			})
		})
	})
	return counts, total, err
}

func (r *Reader) Summary(ctx context.Context) (s Summary, err error) {
	s.Reasons = map[string]int{}
	err = r.db.View(func(tx *bolt.Tx) error {
		counts, total, err := inventory(ctx, tx)
		if err != nil {
			return err
		}
		s.CVEs = tx.Bucket([]byte("vulnerability")).Stats().KeyN
		s.WithMatches, s.Advisories = len(counts), total
		s.WithoutMatches = s.CVEs - s.WithMatches
		var snapshot mirror.Snapshot
		if err := json.Unmarshal(tx.Bucket([]byte("ncsc-metadata")).Get([]byte("snapshot")), &snapshot); err != nil {
			return err
		}
		s.SourceComplete, s.SourceIndexed = snapshot.Complete && tx.Bucket([]byte("ncsc-csaf")).Stats().KeyN == snapshot.Indexed, snapshot.Indexed
		// Build-time reason totals are optional. Check that the sidecar belongs
		// to this build before using it; hashing an 11 GB database is unnecessary.
		raw, err := os.ReadFile(filepath.Join(r.cache, "coverage.json"))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		var report build.Report
		if err := json.Unmarshal(raw, &report); err != nil {
			return err
		}
		raw, err = os.ReadFile(filepath.Join(r.cache, "db", "metadata.json"))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		var metadata build.Metadata
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return err
		}
		if report.Vulnerabilities != s.CVEs || report.VulnerabilitiesWithMatches != s.WithMatches || report.Advisories != total || !report.BuiltAt.Equal(metadata.DownloadedAt) {
			return fmt.Errorf("coverage.json does not describe this database build")
		}
		if report.PolicyVersion != "" {
			var stored struct {
				Version string `json:"version"`
			}
			if e := json.Unmarshal(tx.Bucket([]byte("ncsc-metadata")).Get([]byte("conversion-policy")), &stored); e != nil {
				return fmt.Errorf("stored policy: %w", e)
			}
			if stored.Version != report.PolicyVersion {
				return fmt.Errorf("coverage.json policy differs from this database build")
			}
		}
		s.ReasonsAvailable = true
		s.PolicyVersion = report.PolicyVersion
		if s.PolicyVersion == "" {
			s.PolicyVersion = "unavailable (legacy build)"
		}
		s.UncertainCandidates = report.CandidateObservations
		for reason, count := range report.UnmappedReasons {
			s.Reasons[reason] = count
			s.ExcludedProducts += count
		}
		return nil
	})
	return s, err
}

func (r *Reader) Detail(ctx context.Context, cve string) (d Detail, err error) {
	err = r.db.View(func(tx *bolt.Tx) error {
		var e error
		d, e = detail(ctx, tx, cve, true)
		return e
	})
	return d, err
}

func detail(ctx context.Context, tx *bolt.Tx, cve string, collectProducts bool) (d Detail, err error) {
	d = Detail{CVE: cve, Reasons: map[string]int{}, Products: []Product{}}
	if err := ctx.Err(); err != nil {
		return d, err
	}
	var policy struct {
		Version string `json:"version"`
	}
	if raw := tx.Bucket([]byte("ncsc-metadata")).Get([]byte("conversion-policy")); len(raw) > 0 {
		if err := json.Unmarshal(raw, &policy); err != nil {
			return d, err
		}
		if policy.Version != csaf.PolicyVersion {
			return d, fmt.Errorf("unsupported recorded conversion policy %q", policy.Version)
		}
		d.PolicyVersion, d.PolicyAvailable = policy.Version, true
	} else {
		d.PolicyVersion = "unavailable (legacy build)"
	}
	raw := tx.Bucket([]byte("vulnerability")).Get([]byte(cve))
	if raw == nil {
		return d, fmt.Errorf("%s is absent from this built database's source inventory; no exclusion reason is available (it may be outside the snapshot)", cve)
	}
	var record struct{ Custom struct{ CSAFKey string } }
	if err := json.Unmarshal(raw, &record); err != nil {
		return d, err
	}
	raw, err = mirror.Decompress(tx.Bucket([]byte("ncsc-csaf")).Get([]byte(record.Custom.CSAFKey)))
	if err != nil {
		return d, err
	}
	doc, err := csaf.Decode(raw)
	if err != nil {
		return d, err
	}
	for _, v := range doc.Vulnerabilities {
		if v.CVE != cve {
			continue
		}
		d.Title, d.Source = v.Title, mirror.Directory+record.Custom.CSAFKey
		products := doc.Products()
		entries, candidates, unmapped := csaf.Convert(v, products)
		candidateByProduct := map[string]*csaf.Candidate{}
		if d.PolicyAvailable {
			for _, candidate := range candidates {
				root := tx.Bucket([]byte("ncsc-candidates"))
				if root == nil {
					return d, fmt.Errorf("candidate index missing")
				}
				b := root.Bucket([]byte(candidate.Bucket + "\x00" + candidate.Package))
				if b == nil {
					return d, fmt.Errorf("candidate package missing")
				}
				var c csaf.Candidate
				if e := json.Unmarshal(b.Get([]byte(candidate.CVE+"\x00"+candidate.ProductID)), &c); e != nil {
					return d, fmt.Errorf("candidate missing or corrupt: %w", e)
				}
				candidateByProduct[c.ProductID] = &c
			}
		}
		failures := map[string]string{}
		for _, u := range unmapped {
			failures[u.Status+"\x00"+u.ProductID] = u.Reason
		}
		mapped := map[string]bool{}
		for _, entry := range entries {
			b := tx.Bucket([]byte(entry.Bucket))
			if b == nil || b.Bucket([]byte(entry.Package)) == nil {
				continue
			}
			data := b.Bucket([]byte(entry.Package)).Get([]byte(cve))
			if data == nil {
				continue
			}
			var provenance struct {
				Custom struct{ NCSCProductIDs []string }
			}
			if err := json.Unmarshal(data, &provenance); err != nil {
				return d, err
			}
			for _, pid := range provenance.Custom.NCSCProductIDs {
				mapped[pid] = true
			}
			d.Advisories++
		}
		statuses := make([]string, 0, len(v.ProductStatus))
		for status := range v.ProductStatus {
			statuses = append(statuses, status)
		}
		sort.Strings(statuses)
		for _, status := range statuses {
			ids := append([]string(nil), v.ProductStatus[status]...)
			sort.Strings(ids)
			for _, pid := range ids {
				if err := ctx.Err(); err != nil {
					return d, err
				}
				p := products[pid]
				identity, _ := csaf.Identify(p)
				item := Product{ID: pid, Status: status, Source: p, PackageName: p.PackageName, Version: p.Version, Vendor: p.Vendor, Family: p.Family}
				switch {
				case failures[status+"\x00"+pid] != "":
					item.Outcome, item.Reason = "excluded", failures[status+"\x00"+pid]
				case status == "known_affected" && candidateByProduct[pid] != nil:
					item.Outcome, item.Reason, item.Candidate = "uncertain", "affected_versions_unspecified", candidateByProduct[pid]
				case status == "first_fixed" && identity.Ecosystem != "debian" && identity.Ecosystem != "ubuntu":
					item.Outcome, item.Reason = "ignored", "first_fixed_non_os"
				case (status == "known_affected" || status == "first_fixed") && mapped[pid]:
					item.Outcome = "matched"
				case !d.PolicyAvailable && (status == "known_affected" || status == "first_fixed"):
					item.Outcome, item.Reason = "excluded", "conversion_policy_unavailable"
				case status == "known_affected":
					item.Outcome, item.Reason = "excluded", "missing_database_advisory"
				case status == "first_fixed":
					item.Outcome, item.Reason = "excluded", "missing_database_advisory"
				default:
					item.Outcome, item.Reason = "ignored", "status_not_used_for_matching"
				}
				item.Explanation = Explain(item.Reason)
				switch item.Outcome {
				case "matched":
					d.Matched++
				case "excluded":
					d.Excluded++
					d.Reasons[item.Reason]++
				case "ignored":
					d.Ignored++
				case "uncertain":
					d.Uncertain++
				}
				if collectProducts && (item.Outcome == "excluded" || item.Outcome == "uncertain") {
					d.Products = append(d.Products, item)
				}
			}
		}
		return d, nil
	}
	return d, fmt.Errorf("%s is missing from its archived source document", cve)
}

// List uses a CVE cursor so later pages do not decode earlier source documents.
func (r *Reader) List(ctx context.Context, after string, limit int) (page Page, err error) {
	page.Rows = []Row{}
	err = r.db.View(func(tx *bolt.Tx) error {
		counts, _, err := inventory(ctx, tx)
		if err != nil {
			return err
		}
		cursor := tx.Bucket([]byte("vulnerability")).Cursor()
		key, _ := cursor.First()
		if after != "" {
			key, _ = cursor.Seek([]byte(after))
			if string(key) == after {
				key, _ = cursor.Next()
			}
		}
		for ; key != nil; key, _ = cursor.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			cve := string(key)
			if counts[cve] > 0 {
				continue
			}
			if len(page.Rows) == limit {
				page.NextAfter = page.Rows[len(page.Rows)-1].CVE
				break
			}
			d, err := detail(ctx, tx, cve, false)
			if err != nil {
				return err
			}
			page.Rows = append(page.Rows, Row{CVE: cve, Advisories: counts[cve], Excluded: d.Excluded, Uncertain: d.Uncertain, Ignored: d.Ignored, Reasons: d.Reasons})
		}
		return nil
	})
	return page, err
}
