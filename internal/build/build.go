// Package build writes the schema-v2 buckets consumed by stock Trivy.
package build

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"ncsc-trivy-db/internal/csaf"
	"ncsc-trivy-db/internal/mirror"
)

type Options struct {
	Mirror, Output string
	AllowPartial   bool
	Validity       time.Duration
	WaitForMirror  bool
}
type Report struct {
	Source                     string          `json:"source"`
	SchemaVersion              int             `json:"schema_version"`
	BuiltAt                    time.Time       `json:"built_at"`
	Snapshot                   mirror.Snapshot `json:"snapshot"`
	Complete                   bool            `json:"complete"`
	Documents                  int             `json:"documents"`
	Vulnerabilities            int             `json:"vulnerabilities"`
	VulnerabilitiesWithMatches int             `json:"vulnerabilities_with_matches"`
	Advisories                 int             `json:"advisories"`
	Buckets                    map[string]int  `json:"buckets"`
	UnmappedReasons            map[string]int  `json:"unmapped_reasons"`
	DatabaseSHA256             string          `json:"database_sha256"`
	ArchiveSHA256              string          `json:"archive_sha256"`
	PolicyVersion              string          `json:"policy_version"`
	ConverterRevision          string          `json:"converter_revision"`
	CandidateObservations      int             `json:"candidate_observations"`
	SupportedObservations      int             `json:"supported_observations"`
	IgnoredObservations        int             `json:"ignored_observations"`
	ProductObservations        int             `json:"product_observations"`
	IndexSHA256                string          `json:"index_sha256"`
}

func revision() string {
	info, ok := debug.ReadBuildInfo()
	if ok {
		var revision string
		modified := false
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				revision = s.Value
			}
			if s.Key == "vcs.modified" && s.Value == "true" {
				modified = true
			}
		}
		if revision != "" {
			if modified {
				return revision + "+modified"
			}
			return revision
		}
	}
	return "unknown-revision"
}

type Metadata struct {
	Version                             int
	NextUpdate, UpdatedAt, DownloadedAt time.Time
}
type DataSource struct{ ID, Name, URL string }

func severity(score float64) int {
	switch {
	case score >= 9:
		return 4
	case score >= 7:
		return 3
	case score >= 4:
		return 2
	case score > 0:
		return 1
	default:
		return 0
	}
}

var severities = []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func details(d csaf.Document, v csaf.Vulnerability, path string, raw []byte) map[string]any {
	var descriptions []string
	for _, n := range v.Notes {
		if n.Category == "description" || n.Category == "summary" {
			descriptions = append(descriptions, n.Text)
		}
	}
	descriptions = csaf.Unique(descriptions)
	refs := []string{mirror.Directory + path}
	for _, r := range v.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}
	cvss := map[string]any{}
	for _, score := range v.Scores {
		for _, kind := range []string{"cvss_v2", "cvss_v3", "cvss_v4"} {
			var c struct {
				BaseScore float64 `json:"baseScore"`
				Vector    string  `json:"vectorString"`
			}
			if b, ok := score[kind]; ok && json.Unmarshal(b, &c) == nil {
				prefix := map[string]string{"cvss_v2": "V2", "cvss_v3": "V3", "cvss_v4": "V40"}[kind]
				old, _ := cvss[prefix+"Score"].(float64)
				if c.BaseScore >= old {
					cvss[prefix+"Score"] = c.BaseScore
					cvss[prefix+"Vector"] = c.Vector
				}
			}
		}
	}
	custom := map[string]any{}
	// NCSC publishes CVSS v4 and additional risk metrics as CSAF notes.
	for _, n := range v.Notes {
		switch n.Title {
		case "CVSSV4":
			cvss["V40Vector"] = n.Text
		case "CVSSV4 base score":
			if score, e := strconv.ParseFloat(n.Text, 64); e == nil && score >= 0 && score <= 10 {
				cvss["V40Score"] = score
			}
		case "EPSS", "NCSC Score":
			custom[n.Title] = n.Text
		}
	}
	maxSeverity := 0
	for _, generation := range []string{"V40", "V3", "V2"} {
		if score, ok := cvss[generation+"Score"].(float64); ok {
			maxSeverity = severity(score)
			if generation == "V2" && maxSeverity > 3 {
				maxSeverity = 3
			}
			break
		}
	}
	h := sha256.Sum256(raw)
	custom["NCSCSource"] = mirror.Directory + path
	custom["CSAFSHA256"] = hex.EncodeToString(h[:])
	custom["CSAFBucket"] = "ncsc-csaf"
	custom["CSAFKey"] = path
	out := map[string]any{"Title": v.Title, "Description": strings.Join(descriptions, "\n\n"), "Severity": severities[maxSeverity], "VendorSeverity": map[string]int{csaf.SourceID: maxSeverity}, "CVSS": map[string]any{csaf.SourceID: cvss}, "References": csaf.Unique(refs), "Custom": custom}
	if v.CWE.ID != "" {
		out["CweIDs"] = []string{v.CWE.ID}
	}
	// release_date is the vulnerability's release date, whereas tracking dates
	// represent this NCSC document. Do not relabel NCSC ingestion as CVE publication.
	if t, e := time.Parse(time.RFC3339Nano, v.ReleaseDate); e == nil {
		out["PublishedDate"] = t.UTC()
	}
	if t, e := time.Parse(time.RFC3339Nano, d.Document.Tracking.CurrentReleaseDate); e == nil {
		out["LastModifiedDate"] = t.UTC()
	}
	return out
}

func putJSON(b *bolt.Bucket, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), data)
}
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0644)
}

func Build(ctx context.Context, o Options) (report Report, err error) {
	if o.Output == "" || o.Validity <= 0 {
		return report, errors.New("output and a positive validity are required")
	}
	o.Output = filepath.Clean(o.Output)
	if info, e := os.Lstat(o.Output); e == nil {
		if !info.IsDir() {
			return report, fmt.Errorf("output must be a directory: %s", o.Output)
		}
	} else if !os.IsNotExist(e) {
		return report, e
	}
	in, err := mirror.OpenContext(ctx, o.Mirror, true, o.WaitForMirror)
	if err != nil {
		return report, err
	}
	defer in.Close()
	snapshot, err := mirror.ReadSnapshot(in)
	if err != nil {
		return report, err
	}
	if !snapshot.Complete && !o.AllowPartial {
		return report, fmt.Errorf("mirror is incomplete (%d/%d); run sync to completion; --allow-partial is for tests only", snapshot.Available, snapshot.Indexed)
	}
	if err = os.MkdirAll(filepath.Dir(o.Output), 0755); err != nil {
		return report, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(o.Output), ".ncsc-build-")
	if err != nil {
		return report, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(stage)
		}
	}()
	if err = os.Mkdir(filepath.Join(stage, "db"), 0755); err != nil {
		return report, err
	}
	dbPath := filepath.Join(stage, "db", "trivy.db")
	out, err := bolt.Open(dbPath, 0644, nil)
	if err != nil {
		return report, err
	}
	defer out.Close()
	report = Report{Source: mirror.Directory, SchemaVersion: 2, BuiltAt: time.Now().UTC(), Snapshot: snapshot, Complete: snapshot.Complete, Buckets: map[string]int{}, UnmappedReasons: map[string]int{}, PolicyVersion: csaf.PolicyVersion, ConverterRevision: revision()}
	f, err := os.Create(filepath.Join(stage, "unmapped-products.ndjson.gz"))
	if err != nil {
		return report, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	unmappedEncoder := json.NewEncoder(gz)
	err = in.View(func(read *bolt.Tx) error {
		inv := read.Bucket([]byte("inventory"))
		docs := read.Bucket([]byte("documents"))
		revs := read.Bucket([]byte("revisions"))
		if inv == nil || docs == nil || revs == nil {
			return errors.New("invalid mirror buckets")
		}
		tx, e := out.Begin(true)
		if e != nil {
			return e
		}
		defer func() {
			if tx != nil {
				tx.Rollback()
			}
		}()
		for _, name := range []string{"vulnerability", "data-source", "ncsc-csaf", "ncsc-metadata", "ncsc-candidates"} {
			if _, e = tx.CreateBucketIfNotExists([]byte(name)); e != nil {
				return e
			}
		}
		if e = putJSON(tx.Bucket([]byte("ncsc-metadata")), "conversion-policy", struct {
			Version string `json:"version"`
		}{csaf.PolicyVersion}); e != nil {
			return e
		}
		for _, key := range []string{"provider-metadata.json", "index.txt", "changes.csv", "snapshot"} {
			if b := read.Bucket([]byte("metadata")).Get([]byte(key)); b != nil {
				if e = tx.Bucket([]byte("ncsc-metadata")).Put([]byte(key), b); e != nil {
					return e
				}
			}
		}
		indexHash := sha256.Sum256(read.Bucket([]byte("metadata")).Get([]byte("index.txt")))
		report.IndexSHA256 = hex.EncodeToString(indexHash[:])
		seen := map[string]bool{}
		e = inv.ForEach(func(k, rev []byte) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			compressed := docs.Get(k)
			if compressed == nil || string(revs.Get(k)) != string(rev) {
				if o.AllowPartial {
					report.Complete = false
					return nil
				}
				return fmt.Errorf("missing/stale document: %s", k)
			}
			raw, e := mirror.Decompress(compressed)
			if e != nil {
				return e
			}
			d, e := csaf.Decode(raw)
			if e != nil {
				return fmt.Errorf("%s: %w", k, e)
			}
			if e = tx.Bucket([]byte("ncsc-csaf")).Put(k, compressed); e != nil {
				return e
			}
			products := d.Products()
			for _, v := range d.Vulnerabilities {
				if v.CVE == "" || seen[v.CVE] {
					return fmt.Errorf("missing or duplicate CVE %q in %s", v.CVE, k)
				}
				seen[v.CVE] = true
				if e = putJSON(tx.Bucket([]byte("vulnerability")), v.CVE, details(d, v, string(k), raw)); e != nil {
					return e
				}
				entries, candidates, unmapped := csaf.Convert(v, products)
				rawHash := sha256.Sum256(raw)
				for _, c := range candidates {
					c.SourcePath = mirror.Directory + string(k)
					c.CSAFSHA256 = hex.EncodeToString(rawHash[:])
					b, e := tx.Bucket([]byte("ncsc-candidates")).CreateBucketIfNotExists([]byte(c.Bucket + "\x00" + c.Package))
					if e != nil {
						return e
					}
					if e = putJSON(b, c.CVE+"\x00"+c.ProductID, c); e != nil {
						return e
					}
					report.CandidateObservations++
				}
				for status, ids := range v.ProductStatus {
					report.ProductObservations += len(ids)
					if status != "known_affected" && status != "first_fixed" {
						report.IgnoredObservations += len(ids)
					} else if status == "first_fixed" {
						for _, pid := range ids {
							id, _ := csaf.Identify(products[pid])
							if id.Ecosystem != "debian" && id.Ecosystem != "ubuntu" && id.Ecosystem != "alpine" {
								report.IgnoredObservations++
							}
						}
					}
				}
				for _, entry := range entries {
					ids := entry.Advisory.Custom["NCSCProductIDs"].([]string)
					report.SupportedObservations += len(ids)
				}
				if len(entries) > 0 {
					report.VulnerabilitiesWithMatches++
				}
				for _, u := range unmapped {
					report.UnmappedReasons[u.Reason]++
					if e = unmappedEncoder.Encode(u); e != nil {
						return e
					}
				}
				for _, entry := range entries {
					entry.Advisory.Custom["NCSCSource"] = mirror.Directory + string(k)
					entry.Advisory.Custom["CSAFSHA256"] = hex.EncodeToString(rawHash[:])
					b, e := tx.CreateBucketIfNotExists([]byte(entry.Bucket))
					if e != nil {
						return e
					}
					p, e := b.CreateBucketIfNotExists([]byte(entry.Package))
					if e != nil {
						return e
					}
					if e = putJSON(p, entry.ID, entry.Advisory); e != nil {
						return e
					}
					if e = putJSON(tx.Bucket([]byte("data-source")), entry.Bucket, DataSource{csaf.SourceID, csaf.SourceName, mirror.Directory}); e != nil {
						return e
					}
					report.Advisories++
					report.Buckets[entry.Bucket]++
				}
				report.Vulnerabilities++
			}
			report.Documents++
			if report.Documents%500 == 0 {
				if e = tx.Commit(); e != nil {
					return e
				}
				tx, e = out.Begin(true)
				if e != nil {
					return e
				}
			}
			if report.Documents%10000 == 0 {
				log.Printf("build: %d documents, %d package advisories", report.Documents, report.Advisories)
			}
			return nil
		})
		if e != nil {
			return e
		}
		return tx.Commit()
	})
	if err != nil {
		return report, err
	}
	if report.Documents != snapshot.Indexed {
		report.Complete = false
	}
	if report.ProductObservations != report.SupportedObservations+report.CandidateObservations+sumReasons(report.UnmappedReasons)+report.IgnoredObservations {
		return report, fmt.Errorf("conversion outcomes do not reconcile: %d observations", report.ProductObservations)
	}
	if !report.Complete && !o.AllowPartial {
		return report, errors.New("incomplete build refused")
	}
	if err = gz.Close(); err != nil {
		return report, err
	}
	if err = f.Close(); err != nil {
		return report, err
	}
	if err = out.Close(); err != nil {
		return report, err
	}
	metadata := Metadata{Version: 2, UpdatedAt: snapshot.StartedAt, NextUpdate: snapshot.StartedAt.Add(o.Validity), DownloadedAt: report.BuiltAt}
	if err = writeJSON(filepath.Join(stage, "db", "metadata.json"), metadata); err != nil {
		return report, err
	}
	if report.DatabaseSHA256, err = hashFile(dbPath); err != nil {
		return report, err
	}
	archivePath := filepath.Join(stage, "db.tar.gz")
	if err = archive(archivePath, filepath.Join(stage, "db")); err != nil {
		return report, err
	}
	if report.ArchiveSHA256, err = hashFile(archivePath); err != nil {
		return report, err
	}
	if err = writeJSON(filepath.Join(stage, "coverage.json"), report); err != nil {
		return report, err
	}
	if err = os.WriteFile(filepath.Join(stage, "SHA256SUMS"), []byte(report.DatabaseSHA256+"  db/trivy.db\n"+report.ArchiveSHA256+"  db.tar.gz\n"), 0644); err != nil {
		return report, err
	}
	if err = publish(stage, o.Output); err != nil {
		return report, err
	}
	log.Printf("database built: %s (%d documents, %d CVEs, %d advisories, %d supported observations, %d uncertain candidates, %d exclusions; complete=%t); details: %s/coverage.json", o.Output, report.Documents, report.Vulnerabilities, report.Advisories, report.SupportedObservations, report.CandidateObservations, sumReasons(report.UnmappedReasons), report.Complete, o.Output)
	return report, nil
}

// publish keeps the previous output until the new build is ready and restores
// it if publishing fails. Old reports and scan results are replaced as well.
func publish(stage, output string) error {
	if _, err := os.Lstat(output); os.IsNotExist(err) {
		return os.Rename(stage, output)
	} else if err != nil {
		return err
	}
	backup, err := os.MkdirTemp(filepath.Dir(output), ".ncsc-previous-")
	if err != nil {
		return err
	}
	previous := filepath.Join(backup, "output")
	if err = os.Rename(output, previous); err != nil {
		os.Remove(backup)
		return err
	}
	if err = os.Rename(stage, output); err != nil {
		if restoreErr := os.Rename(previous, output); restoreErr != nil {
			return fmt.Errorf("publish build: %w; restore previous output from %s: %v", err, previous, restoreErr)
		}
		os.Remove(backup)
		return err
	}
	if err = os.RemoveAll(backup); err != nil {
		return fmt.Errorf("build published, but removing previous output at %s failed: %w", backup, err)
	}
	return nil
}

func sumReasons(reasons map[string]int) (n int) {
	for _, count := range reasons {
		n += count
	}
	return
}

func hashFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func archive(path, dbdir string) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	for _, name := range []string{"trivy.db", "metadata.json"} {
		f, e := os.Open(filepath.Join(dbdir, name))
		if e != nil {
			return e
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			return e
		}
		e = tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: st.Size()})
		if e == nil {
			_, e = io.Copy(tw, f)
		}
		f.Close()
		if e != nil {
			return e
		}
	}
	if err = tw.Close(); err != nil {
		return err
	}
	if err = gz.Close(); err != nil {
		return err
	}
	return f.Close()
}

// ExportCSAF recovers the exact original JSON bytes from a built database.
func ExportCSAF(path, key string, w io.Writer) error {
	if !mirror.DocumentPath.MatchString(key) {
		return errors.New("expected year/cve-yyyy-nnnn.json")
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("ncsc-csaf"))
		if b == nil {
			return errors.New("no archived NCSC CSAF in database")
		}
		v := b.Get([]byte(key))
		if v == nil {
			return errors.New("CSAF document not found")
		}
		raw, e := mirror.Decompress(v)
		if e != nil {
			return e
		}
		_, e = w.Write(raw)
		return e
	})
}
