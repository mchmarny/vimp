package snyk

import (
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vulctl/internal/source"
	"github.com/mchmarny/vulctl/internal/util"
	"github.com/mchmarny/vulctl/pkg/vulnerability"
	"github.com/pkg/errors"
)

// Convert converts JSON to a list of common vulnerabilities.
func Convert(s *source.Source) ([]*vulnerability.Item, error) {
	if s == nil || s.Data == nil {
		return nil, errors.New("valid source required")
	}

	if !s.Data.Search("vulnerabilities").Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make([]*vulnerability.Item, 0)

	for _, v := range s.Data.Search("vulnerabilities").Children() {
		vul := mapVulnerability(v)
		if vul == nil {
			continue
		}

		list = append(list, vul)
	}

	return list, nil
}

func mapVulnerability(v *gabs.Container) *vulnerability.Item {
	c := v.Search("cvssDetails")
	if !c.Exists() {
		return nil
	}

	item := &vulnerability.Item{
		ID:       util.ToString(v.Search("identifiers", "CVE").Index(0).Data()),
		Package:  util.ToString(v.Search("name").Data()),
		Version:  util.ToString(v.Search("version").Data()),
		Severity: strings.ToLower(util.ToString(v.Search("severity").Data())),
		Score:    util.ToFloat32(c.Search("cvssScore").Data()),
		IsFixed:  util.ToBool(v.Search("isUpgradable").Data()),
	}

	return item
}
