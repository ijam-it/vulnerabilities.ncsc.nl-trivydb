package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	bolt "go.etcd.io/bbolt"
	"ncsc-trivy-db/internal/build"
	"ncsc-trivy-db/internal/csaf"
)

// ConversionDifference compares NCSC findings directly. Each source-vs-official
// report alone cannot reveal findings lost by a converter change.
type ConversionDifference struct {
	SBOMSHA256        string                     `json:"sbom_sha256"`
	TrivyVersion      string                     `json:"trivy_version"`
	BeforeFindings    int                        `json:"before_findings"`
	AfterFindings     int                        `json:"after_findings"`
	Added             []Finding                  `json:"added"`
	Removed           []Finding                  `json:"removed"`
	MetadataChanges   []ConversionMetadataChange `json:"metadata_changes"`
	BeforeCandidates  int                        `json:"before_candidates"`
	AfterCandidates   int                        `json:"after_candidates"`
	CandidatesAdded   []csaf.Candidate           `json:"candidates_added"`
	CandidatesRemoved []csaf.Candidate           `json:"candidates_removed"`
	BeforePolicy      string                     `json:"before_policy"`
	AfterPolicy       string                     `json:"after_policy"`
}

type ConversionMetadataChange struct {
	Before Finding `json:"before"`
	After  Finding `json:"after"`
}

func readBuild(cache string) (build.Report, error) {
	var report build.Report
	raw, e := os.ReadFile(filepath.Join(cache, "coverage.json"))
	if e != nil {
		return report, e
	}
	e = json.Unmarshal(raw, &report)
	return report, e
}

func readComparison(path string) (Report, error) {
	var report Report
	raw, e := os.ReadFile(path)
	if e != nil {
		return report, e
	}
	e = json.Unmarshal(raw, &report)
	return report, e
}

func ncscFindings(report Report) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range append(append([]Finding{}, report.Comparison.Shared...), report.Comparison.NCSCOnly...) {
		out[key(f)] = f
	}
	return out
}

func candidateIndex(ctx context.Context, cache string) (map[string]csaf.Candidate, error) {
	out := map[string]csaf.Candidate{}
	db, e := bolt.Open(filepath.Join(cache, "db", "trivy.db"), 0600, &bolt.Options{ReadOnly: true})
	if e != nil {
		return out, e
	}
	defer db.Close()
	e = db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte("ncsc-candidates"))
		if root == nil {
			return nil
		} // Legacy baseline builds predate this index.
		return root.ForEach(func(packageKey, value []byte) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			if value != nil {
				return fmt.Errorf("invalid candidate index")
			}
			return root.Bucket(packageKey).ForEach(func(k, v []byte) error {
				var c csaf.Candidate
				if e := json.Unmarshal(v, &c); e != nil {
					return e
				}
				out[string(packageKey)+"\x00"+string(k)] = c
				return nil
			})
		})
	})
	return out, e
}

func CompareConversion(ctx context.Context, beforePath, afterPath, beforeCache, afterCache string) (out ConversionDifference, err error) {
	before, e := readComparison(beforePath)
	if e != nil {
		return out, e
	}
	after, e := readComparison(afterPath)
	if e != nil {
		return out, e
	}
	if before.SBOMSHA256 != after.SBOMSHA256 || before.TrivyVersion != after.TrivyVersion || before.Databases["trivy"].SHA256 != after.Databases["trivy"].SHA256 {
		return out, fmt.Errorf("before/after comparison inputs or scanner differ")
	}
	beforeBuild, e := readBuild(beforeCache)
	if e != nil {
		return out, e
	}
	afterBuild, e := readBuild(afterCache)
	if e != nil {
		return out, e
	}
	if beforeBuild.Source != afterBuild.Source || !reflect.DeepEqual(beforeBuild.Snapshot, afterBuild.Snapshot) {
		return out, fmt.Errorf("source snapshots differ")
	}
	if before.Databases["ncsc"].SHA256 != beforeBuild.DatabaseSHA256 || after.Databases["ncsc"].SHA256 != afterBuild.DatabaseSHA256 {
		return out, fmt.Errorf("report database identity differs from cache")
	}
	out = ConversionDifference{SBOMSHA256: before.SBOMSHA256, TrivyVersion: before.TrivyVersion, Added: []Finding{}, Removed: []Finding{}, MetadataChanges: []ConversionMetadataChange{}, CandidatesAdded: []csaf.Candidate{}, CandidatesRemoved: []csaf.Candidate{}, BeforePolicy: beforeBuild.PolicyVersion, AfterPolicy: afterBuild.PolicyVersion}
	if out.BeforePolicy == "" {
		out.BeforePolicy = "unavailable (legacy build)"
	}
	if out.AfterPolicy == "" {
		out.AfterPolicy = "unavailable (legacy build)"
	}
	a, b := ncscFindings(before), ncscFindings(after)
	out.BeforeFindings, out.AfterFindings = len(a), len(b)
	for k, old := range a {
		if newer, ok := b[k]; !ok {
			out.Removed = append(out.Removed, old)
		} else if old.Severity != newer.Severity || old.FixedVersion != newer.FixedVersion {
			out.MetadataChanges = append(out.MetadataChanges, ConversionMetadataChange{Before: old, After: newer})
		}
	}
	for k, newer := range b {
		if _, ok := a[k]; !ok {
			out.Added = append(out.Added, newer)
		}
	}
	sort.Slice(out.Added, func(i, j int) bool { return key(out.Added[i]) < key(out.Added[j]) })
	sort.Slice(out.Removed, func(i, j int) bool { return key(out.Removed[i]) < key(out.Removed[j]) })
	sort.Slice(out.MetadataChanges, func(i, j int) bool { return key(out.MetadataChanges[i].Before) < key(out.MetadataChanges[j].Before) })
	ca, e := candidateIndex(ctx, beforeCache)
	if e != nil {
		return out, e
	}
	cb, e := candidateIndex(ctx, afterCache)
	if e != nil {
		return out, e
	}
	out.BeforeCandidates, out.AfterCandidates = len(ca), len(cb)
	for k, c := range ca {
		if _, ok := cb[k]; !ok {
			out.CandidatesRemoved = append(out.CandidatesRemoved, c)
		}
	}
	for k, c := range cb {
		if _, ok := ca[k]; !ok {
			out.CandidatesAdded = append(out.CandidatesAdded, c)
		}
	}
	sort.Slice(out.CandidatesAdded, func(i, j int) bool {
		return out.CandidatesAdded[i].CVE+out.CandidatesAdded[i].ProductID < out.CandidatesAdded[j].CVE+out.CandidatesAdded[j].ProductID
	})
	sort.Slice(out.CandidatesRemoved, func(i, j int) bool {
		return out.CandidatesRemoved[i].CVE+out.CandidatesRemoved[i].ProductID < out.CandidatesRemoved[j].CVE+out.CandidatesRemoved[j].ProductID
	})
	return out, nil
}
