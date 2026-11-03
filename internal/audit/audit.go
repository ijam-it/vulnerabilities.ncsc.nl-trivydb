// Package audit independently checks the full source-to-database inventory.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"ncsc-trivy-db/internal/csaf"
	"ncsc-trivy-db/internal/mirror"
)

type Report struct {
	VerifiedAt                                      time.Time `json:"verified_at"`
	Complete                                        bool      `json:"complete"`
	Source                                          string    `json:"source"`
	IndexSHA256                                     string    `json:"index_sha256"`
	Indexed, Documents, Vulnerabilities, Advisories int
	Buckets                                         map[string]int `json:"buckets"`
	Candidates                                      int            `json:"candidates"`
	PolicyVersion                                   string         `json:"policy_version"`
}

func Check(ctx context.Context, mirrorPath, databasePath string) (report Report, err error) {
	in, err := mirror.Open(mirrorPath, true)
	if err != nil {
		return report, err
	}
	defer in.Close()
	out, err := mirror.Open(databasePath, true)
	if err != nil {
		return report, err
	}
	defer out.Close()
	snapshot, err := mirror.ReadSnapshot(in)
	if err != nil {
		return report, err
	}
	if !snapshot.Complete {
		return report, fmt.Errorf("cannot audit incomplete source: %d/%d", snapshot.Available, snapshot.Indexed)
	}
	report = Report{VerifiedAt: time.Now().UTC(), Source: mirror.Directory, Indexed: snapshot.Indexed, Buckets: map[string]int{}}
	err = in.View(func(source *bolt.Tx) error {
		return out.View(func(db *bolt.Tx) error {
			for _, name := range []string{"inventory", "documents", "revisions", "metadata"} {
				if source.Bucket([]byte(name)) == nil {
					return fmt.Errorf("source bucket missing: %s", name)
				}
			}
			for _, name := range []string{"ncsc-csaf", "ncsc-metadata", "vulnerability", "data-source"} {
				if db.Bucket([]byte(name)) == nil {
					return fmt.Errorf("database bucket missing: %s", name)
				}
			}
			sourceMeta := source.Bucket([]byte("metadata"))
			dbMeta := db.Bucket([]byte("ncsc-metadata"))
			var policy struct {
				Version string `json:"version"`
			}
			if raw := dbMeta.Get([]byte("conversion-policy")); len(raw) > 0 {
				if err := json.Unmarshal(raw, &policy); err != nil {
					return err
				}
				if policy.Version != csaf.PolicyVersion {
					return fmt.Errorf("unsupported conversion policy: %s", policy.Version)
				}
				if db.Bucket([]byte("ncsc-candidates")) == nil {
					return fmt.Errorf("missing candidate index")
				}
				report.PolicyVersion = policy.Version
			}
			for _, name := range []string{"provider-metadata.json", "index.txt", "changes.csv", "snapshot"} {
				v := sourceMeta.Get([]byte(name))
				if len(v) == 0 || !bytes.Equal(v, dbMeta.Get([]byte(name))) {
					return fmt.Errorf("missing or changed source metadata: %s", name)
				}
			}
			index := sourceMeta.Get([]byte("index.txt"))
			sum := sha256.Sum256(index)
			report.IndexSHA256 = hex.EncodeToString(sum[:])
			indexed := map[string]bool{}
			for _, line := range strings.Split(string(index), "\n") {
				p := strings.TrimPrefix(strings.TrimSpace(line), mirror.Directory)
				if p == "" {
					continue
				}
				if !mirror.DocumentPath.MatchString(p) {
					return fmt.Errorf("invalid index path: %s", p)
				}
				indexed[p] = true
			}
			if len(indexed) != snapshot.Indexed {
				return fmt.Errorf("source index has %d entries, snapshot claims %d", len(indexed), snapshot.Indexed)
			}
			vulnerabilities := map[string]bool{}
			registered := map[string]bool{}
			if err := db.Bucket([]byte("data-source")).ForEach(func(k, v []byte) error {
				var data struct{ ID, Name, URL string }
				if err := json.Unmarshal(v, &data); err != nil {
					return err
				}
				if data.ID != csaf.SourceID || data.Name != csaf.SourceName || data.URL != mirror.Directory {
					return fmt.Errorf("unexpected vulnerability source in %s: %+v", k, data)
				}
				registered[string(k)] = true
				return nil
			}); err != nil {
				return err
			}
			for p := range indexed {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				key := []byte(p)
				rev := source.Bucket([]byte("inventory")).Get(key)
				if len(rev) == 0 || !bytes.Equal(rev, source.Bucket([]byte("revisions")).Get(key)) {
					return fmt.Errorf("source is missing or stale: %s", p)
				}
				compressed := source.Bucket([]byte("documents")).Get(key)
				if len(compressed) == 0 || !bytes.Equal(compressed, db.Bucket([]byte("ncsc-csaf")).Get(key)) {
					return fmt.Errorf("source differs from database archive: %s", p)
				}
				raw, err := mirror.Decompress(compressed)
				if err != nil {
					return err
				}
				d, err := csaf.Decode(raw)
				if err != nil {
					return err
				}
				hash := sha256.Sum256(raw)
				for _, v := range d.Vulnerabilities {
					if v.CVE == "" || vulnerabilities[v.CVE] {
						return fmt.Errorf("missing or duplicate vulnerability ID: %q", v.CVE)
					}
					vulnerabilities[v.CVE] = true
					var details struct {
						Custom         struct{ NCSCSource, CSAFSHA256, CSAFBucket, CSAFKey string }
						VendorSeverity map[string]int
						CVSS           map[string]json.RawMessage
					}
					if err = json.Unmarshal(db.Bucket([]byte("vulnerability")).Get([]byte(v.CVE)), &details); err != nil {
						return fmt.Errorf("%s: %w", v.CVE, err)
					}
					if details.Custom.NCSCSource != mirror.Directory+p || details.Custom.CSAFSHA256 != hex.EncodeToString(hash[:]) || details.Custom.CSAFKey != p || details.Custom.CSAFBucket != "ncsc-csaf" {
						return fmt.Errorf("invalid source provenance for %s", v.CVE)
					}
					for source := range details.VendorSeverity {
						if source != csaf.SourceID {
							return fmt.Errorf("non-NCSC severity for %s", v.CVE)
						}
					}
					for source := range details.CVSS {
						if source != csaf.SourceID {
							return fmt.Errorf("non-NCSC CVSS for %s", v.CVE)
						}
					}
					var entries []csaf.Entry
					if policy.Version == "" {
						entries, _ = csaf.Entries(v, d.Products())
					} else {
						var candidates []csaf.Candidate
						entries, candidates, _ = csaf.Convert(v, d.Products())
						for _, c := range candidates {
							c.SourcePath = mirror.Directory + p
							c.CSAFSHA256 = hex.EncodeToString(hash[:])
							b := db.Bucket([]byte("ncsc-candidates")).Bucket([]byte(c.Bucket + "\x00" + c.Package))
							if b == nil {
								return fmt.Errorf("missing candidate index package: %s/%s", c.Bucket, c.Package)
							}
							expected, e := json.Marshal(c)
							if e != nil {
								return e
							}
							if !bytes.Equal(expected, b.Get([]byte(c.CVE+"\x00"+c.ProductID))) {
								return fmt.Errorf("incorrect candidate: %s/%s", c.CVE, c.ProductID)
							}
							report.Candidates++
						}
					}
					for _, entry := range entries {
						entry.Advisory.Custom["NCSCSource"] = mirror.Directory + p
						entry.Advisory.Custom["CSAFSHA256"] = hex.EncodeToString(hash[:])
						if !registered[entry.Bucket] {
							return fmt.Errorf("unregistered advisory bucket: %s", entry.Bucket)
						}
						b := db.Bucket([]byte(entry.Bucket))
						if b == nil {
							return fmt.Errorf("missing advisory bucket: %s", entry.Bucket)
						}
						b = b.Bucket([]byte(entry.Package))
						if b == nil {
							return fmt.Errorf("missing package: %s", entry.Package)
						}
						expected, e := json.Marshal(entry.Advisory)
						if e != nil {
							return e
						}
						if !bytes.Equal(expected, b.Get([]byte(entry.ID))) {
							return fmt.Errorf("incorrect or missing advisory: %s/%s/%s", entry.Bucket, entry.Package, entry.ID)
						}
						report.Advisories++
						report.Buckets[entry.Bucket]++
					}
					report.Vulnerabilities++
				}
				report.Documents++
			}
			if db.Bucket([]byte("ncsc-csaf")).Stats().KeyN != report.Documents {
				return fmt.Errorf("unexpected extra archived documents")
			}
			if db.Bucket([]byte("vulnerability")).Stats().KeyN != report.Vulnerabilities {
				return fmt.Errorf("unexpected extra vulnerability records")
			}
			if policy.Version != "" {
				count := 0
				if err := db.Bucket([]byte("ncsc-candidates")).ForEach(func(k, v []byte) error {
					if v != nil {
						return fmt.Errorf("unexpected candidate index value")
					}
					return db.Bucket([]byte("ncsc-candidates")).Bucket(k).ForEach(func(_, value []byte) error {
						if value == nil {
							return fmt.Errorf("nested candidate bucket")
						}
						count++
						return nil
					})
				}); err != nil {
					return err
				}
				if count != report.Candidates {
					return fmt.Errorf("unexpected extra candidates")
				}
			}
			return db.ForEach(func(name []byte, b *bolt.Bucket) error {
				if registered[string(name)] {
					count := 0
					if err := b.ForEach(func(pkg, value []byte) error {
						if value != nil {
							return fmt.Errorf("unexpected value in advisory root %s", name)
						}
						child := b.Bucket(pkg)
						return child.ForEach(func(k, v []byte) error {
							if v == nil || !vulnerabilities[string(k)] {
								return fmt.Errorf("unexpected advisory in %s/%s", name, pkg)
							}
							count++
							return nil
						})
					}); err != nil {
						return err
					}
					if count != report.Buckets[string(name)] {
						return fmt.Errorf("unexpected extra advisories in %s", name)
					}
					return nil
				}
				switch string(name) {
				case "ncsc-csaf", "ncsc-metadata", "ncsc-candidates", "vulnerability", "data-source":
					return nil
				default:
					return fmt.Errorf("unexpected database bucket: %s", name)
				}
			})
		})
	})
	if err != nil {
		return report, err
	}
	report.Complete = true
	return report, nil
}
