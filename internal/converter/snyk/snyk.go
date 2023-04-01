package snyk

import (
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vulctl/internal/parser"
	"github.com/mchmarny/vulctl/pkg/data"
	"github.com/pkg/errors"
)

// Convert converts JSON to a list of common vulnerabilities.
func Convert(c *gabs.Container) ([]*data.Vulnerability, error) {
	if c == nil {
		return nil, errors.New("source required")
	}

	v := c.Search("vulnerabilities")
	if !v.Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make([]*data.Vulnerability, 0)

	for _, r := range v.Children() {
		vul := mapVulnerability(r)
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
