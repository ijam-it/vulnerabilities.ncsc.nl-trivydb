package csaf

import (
	"net/url"
	"strings"
)

type bound struct{ op, version string }
type versionInterval struct {
	lower, upper *bound
	point        string
}

func (i versionInterval) contains(v, eco string) bool {
	if i.point != "" {
		order, _ := compareVersions(eco, v, i.point)
		return order == 0
	}
	if i.lower != nil {
		order, _ := compareVersions(eco, v, i.lower.version)
		if order < 0 || (order == 0 && i.lower.op == ">") {
			return false
		}
	}
	if i.upper != nil {
		order, _ := compareVersions(eco, v, i.upper.version)
		if order > 0 || (order == 0 && i.upper.op == "<") {
			return false
		}
	}
	return true
}

// VERS is an ordered sequence, not a list of AND or OR clauses. In particular,
// <1|>2 means two unbounded intervals, while >1|<2 means one bounded interval.
// Exclusions apply to the entire union. Preserve that distinction in Trivy's
// VulnerableVersions, whose elements are ORed and whose comma clauses are ANDed.
func parseRange(raw, eco string) ([]string, string) {
	if raw == "*" {
		return []string{""}, ""
	}
	var included []bound
	var excluded []string
	previousVersion := ""
	for _, token := range strings.Split(raw, "|") {
		if token == "" {
			return nil, "unsupported_version_range"
		}
		op := "="
		v := token
		for _, candidate := range []string{">=", "<=", "!=", ">", "<", "="} {
			if strings.HasPrefix(token, candidate) {
				op = candidate
				v = strings.TrimSpace(strings.TrimPrefix(token, candidate))
				break
			}
		}
		decoded, e := url.PathUnescape(v)
		if e != nil {
			return nil, "unsupported_version_range"
		}
		v = strings.TrimPrefix(decoded, "v")
		if !versionToken.MatchString(v) {
			return nil, "unsupported_version_range"
		}
		if _, err := compareVersions(eco, v, v); err != nil {
			return nil, "unsupported_version_range"
		}
		if previousVersion != "" {
			order, e := compareVersions(eco, previousVersion, v)
			if e != nil {
				return nil, "unsupported_version_range"
			}
			if order >= 0 {
				return nil, "invalid_version_range_order"
			}
		}
		previousVersion = v
		if op == "!=" {
			excluded = append(excluded, v)
		} else {
			included = append(included, bound{op, v})
		}
	}
	// Validate comparator transitions after removing exclusions, per the VERS spec.
	for i := 1; i < len(included); i++ {
		a, b := included[i-1].op, included[i].op
		if (a == "=" || a == "<" || a == "<=") && (b == "<" || b == "<=") {
			return nil, "invalid_version_range_sequence"
		}
		if (a == ">" || a == ">=") && (b == "=" || b == ">" || b == ">=") {
			return nil, "invalid_version_range_sequence"
		}
	}
	equal := "= "
	if eco == "pip" {
		equal = "== "
	}
	var intervals []versionInterval
	for i := 0; i < len(included); i++ {
		b := included[i]
		switch b.op {
		case "=":
			intervals = append(intervals, versionInterval{point: b.version})
		case "<", "<=":
			upper := b
			intervals = append(intervals, versionInterval{upper: &upper})
		case ">", ">=":
			lower := b
			interval := versionInterval{lower: &lower}
			if i+1 < len(included) {
				next := included[i+1]
				interval.upper = &next
				i++
			}
			intervals = append(intervals, interval)
		}
	}
	if len(intervals) == 0 && len(excluded) > 0 {
		intervals = []versionInterval{{}}
	}
	// Split at excluded points. npm's native comparer has no != operator, so
	// expressing the exclusion as two open intervals works across all ecosystems.
	for _, v := range excluded {
		var remaining []versionInterval
		for _, interval := range intervals {
			if !interval.contains(v, eco) {
				remaining = append(remaining, interval)
				continue
			}
			if interval.point != "" {
				continue
			}
			remaining = append(remaining, versionInterval{lower: interval.lower, upper: &bound{"<", v}}, versionInterval{lower: &bound{">", v}, upper: interval.upper})
		}
		intervals = remaining
	}
	var ranges []string
	for _, interval := range intervals {
		if interval.point != "" {
			ranges = append(ranges, equal+interval.point)
			continue
		}
		var clauses []string
		for _, b := range []*bound{interval.lower, interval.upper} {
			if b != nil {
				clauses = append(clauses, b.op+" "+b.version)
			}
		}
		ranges = append(ranges, strings.Join(clauses, ", "))
	}
	if len(ranges) == 0 {
		return nil, "unknown_version"
	}
	return Unique(ranges), ""
}
