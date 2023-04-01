package snyk

import (
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/mchmarny/vulctl/pkg/utils"
	"github.com/pkg/errors"
)

// Convert converts JSON to a list of common vulnerabilities.
func Convert(s *src.Source) (map[string]*types.Vulnerability, error) {
	if s == nil || s.Data == nil {
		return nil, errors.New("valid source required")
	}

	if !s.Data.Search("vulnerabilities").Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make(map[string]*types.Vulnerability, 0)

	for _, v := range s.Data.Search("vulnerabilities").Children() {
		vul := mapVulnerability(v)
		if vul == nil {
			continue
		}

		list[vul.ID] = vul
	}

	return list, nil
}

func mapVulnerability(v *gabs.Container) *types.Vulnerability {
	c := v.Search("cvssDetails")
	if !c.Exists() {
		return nil
	}

	item := &types.Vulnerability{
		ID:       utils.ToString(v.Search("identifiers", "CVE").Index(0).Data()),
		Package:  utils.ToString(v.Search("name").Data()),
		Version:  utils.ToString(v.Search("version").Data()),
		Severity: strings.ToLower(utils.ToString(v.Search("severity").Data())),
		Score:    utils.ToFloat32(c.Search("cvssScore").Data()),
		IsFixed:  utils.ToBool(v.Search("isUpgradable").Data()),
	}

	return item
}
