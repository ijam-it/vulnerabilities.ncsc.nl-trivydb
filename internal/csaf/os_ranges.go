package csaf

import "sort"

// OS ranges have an optional inclusive lower bound and an exclusive upper
// bound. An empty lower bound means unbounded, not version zero.
type osRange struct{ lower, upper string }

type osRangeSet struct {
	ecosystem   string
	affected    []osRange
	firstFixed  []string
	allAffected bool
}

func (s osRangeSet) merge() (osRange, bool) {
	if s.allAffected {
		return osRange{}, true
	}
	ranges := append([]osRange(nil), s.affected...)
	if len(ranges) == 0 {
		for _, fixed := range s.firstFixed {
			ranges = append(ranges, osRange{upper: fixed})
		}
	}
	if len(ranges) == 0 {
		return osRange{}, false
	}
	// Sort all observations before checking for gaps: a later observation can
	// bridge two earlier intervals that would otherwise appear disconnected.
	var compareErr error
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].lower == "" || ranges[j].lower == "" {
			return ranges[i].lower == "" && ranges[j].lower != ""
		}
		order, err := compareVersions(s.ecosystem, ranges[i].lower, ranges[j].lower)
		if err != nil {
			compareErr = err
		}
		return order < 0
	})
	if compareErr != nil {
		return osRange{}, false
	}
	merged := ranges[0]
	for _, next := range ranges[1:] {
		if next.lower != "" {
			order, err := compareVersions(s.ecosystem, next.lower, merged.upper)
			if err != nil || order > 0 {
				return osRange{}, false
			}
		}
		order, err := compareVersions(s.ecosystem, merged.upper, next.upper)
		if err != nil {
			return osRange{}, false
		}
		if order < 0 {
			merged.upper = next.upper
		}
	}
	for _, fixed := range s.firstFixed {
		order, err := compareVersions(s.ecosystem, merged.upper, fixed)
		if err != nil || (merged.lower != "" && order != 0) {
			// A first fix must confirm the upper boundary of a bounded affected
			// set; it must not erase that set's explicit lower boundary.
			return osRange{}, false
		}
		if merged.lower == "" && order < 0 {
			merged.upper = fixed
		}
	}
	return merged, true
}
