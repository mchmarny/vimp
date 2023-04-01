package snyk

import (
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vulctl/internal/parser"
	"github.com/mchmarny/vulctl/pkg/data"
	"github.com/pkg/errors"
)

// Convert converts JSON to a list of common vulnerabilities.
func Convert(path string) ([]*data.Vulnerability, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}

	s, err := gabs.ParseJSONFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse file: %s", path)
	}

	v := s.Search("vulnerabilities")
	if !v.Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make([]*data.Vulnerability, 0)

	for _, c := range v.Children() {
		vul := mapVulnerability(c)
		if vul == nil {
			continue
		}

		list = append(list, vul)
	}

	return list, nil
}

func mapVulnerability(v *gabs.Container) *data.Vulnerability {
	c := v.Search("cvssDetails")
	if !c.Exists() {
		return nil
	}

	item := &data.Vulnerability{
		ID:       parser.ToString(v.Search("identifiers", "CVE").Index(0).Data()),
		Package:  parser.ToString(v.Search("name").Data()),
		Version:  parser.ToString(v.Search("version").Data()),
		Severity: strings.ToLower(parser.ToString(v.Search("severity").Data())),
		Score:    parser.ToFloat32(c.Search("cvssScore").Data()),
		IsFixed:  parser.ToBool(v.Search("isUpgradable").Data()),
	}

	return item
}
