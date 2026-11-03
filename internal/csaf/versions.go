package csaf

import (
	gem "github.com/aquasecurity/go-gem-version"
	npm "github.com/aquasecurity/go-npm-version/pkg"
	pep440 "github.com/aquasecurity/go-pep440-version"
	version "github.com/aquasecurity/go-version/pkg/version"
	apk "github.com/knqyf263/go-apk-version"
	deb "github.com/knqyf263/go-deb-version"
	maven "github.com/masahiro331/go-mvn-version"
	"strings"
)

// Validate with the same parsers used by the corresponding Trivy 0.74 scanners.
func validateConstraints(eco string, constraints []string) error {
	for _, c := range constraints {
		if c == "" {
			continue
		}
		var err error
		switch eco {
		case "pip":
			_, err = pep440.NewSpecifiers(c, pep440.WithPreRelease(true))
		case "npm":
			_, err = npm.NewConstraints(c)
		case "rubygems", "cocoapods":
			_, err = gem.NewConstraints(c)
		case "maven":
			_, err = maven.NewComparer(c)
		case "debian", "ubuntu":
			_, err = deb.NewVersion(strings.TrimPrefix(c, "= "))
		case "alpine":
			_, err = apk.NewVersion(strings.TrimPrefix(c, "= "))
		default:
			_, err = version.NewConstraints(c)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func compareVersions(eco, a, b string) (int, error) {
	switch eco {
	case "pip":
		av, e := pep440.Parse(a)
		if e != nil {
			return 0, e
		}
		bv, e := pep440.Parse(b)
		if e != nil {
			return 0, e
		}
		return av.Compare(bv), nil
	case "npm":
		av, e := npm.NewVersion(a)
		if e != nil {
			return 0, e
		}
		bv, e := npm.NewVersion(b)
		if e != nil {
			return 0, e
		}
		return av.Compare(bv), nil
	case "rubygems", "cocoapods":
		av, e := gem.NewVersion(a)
		if e != nil {
			return 0, e
		}
		bv, e := gem.NewVersion(b)
		if e != nil {
			return 0, e
		}
		return av.Compare(bv), nil
	case "maven":
		av, e := maven.NewVersion(a)
		if e != nil {
			return 0, e
		}
		bv, e := maven.NewVersion(b)
		if e != nil {
			return 0, e
		}
		return av.Compare(bv), nil
	case "debian", "ubuntu":
		av, e := deb.NewVersion(a)
		if e != nil {
			return 0, e
		}
		bv, e := deb.NewVersion(b)
		if e != nil {
			return 0, e
		}
		return av.Compare(bv), nil
	case "alpine":
		av, e := apk.NewVersion(a)
		if e != nil {
			return 0, e
		}
		bv, e := apk.NewVersion(b)
		if e != nil {
			return 0, e
		}
		return av.Compare(bv), nil
	default:
		av, e := version.Parse(a)
		if e != nil {
			return 0, e
		}
		bv, e := version.Parse(b)
		if e != nil {
			return 0, e
		}
		return av.Compare(bv), nil
	}
}
