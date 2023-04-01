package grype

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

	if !s.Data.Search("matches").Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make(map[string]*types.Vulnerability, 0)

	for _, m := range s.Data.Search("matches").Children() {
		vul := mapVulnerability(m)
		if vul == nil {
			continue
		}

		list[vul.ID] = vul
	}

	return list, nil
}

func mapVulnerability(m *gabs.Container) *types.Vulnerability {
	v := m.Search("vulnerability")
	if !v.Exists() {
		return nil
	}

	a := m.Search("artifact")
	if !a.Exists() {
		return nil
	}

	item := &types.Vulnerability{
		ID:       utils.ToString(v.Search("id").Data()),
		Package:  utils.ToString(a.Search("name").Data()),
		Version:  utils.ToString(a.Search("version").Data()),
		Severity: strings.ToLower(utils.ToString(v.Search("severity").Data())),
		Score:    getScore(m),
		IsFixed:  utils.ToString(v.Search("fix", "state").Data()) == "fixed",
	}

	return item
}

func getScore(v *gabs.Container) float32 {
	rvList := v.Search("relatedVulnerabilities").Children()
	var rv *gabs.Container
	for _, rvNode := range rvList {
		if rvNode.Search("namespace").Data().(string) == "nvd:cpe" {
			rv = rvNode
			break
		}
	}
	if rv == nil {
		return 0
	}

	for _, cvss := range rv.Search("cvss").Children() {
		switch cvss.Search("version").Data().(string) {
		case "2.0":
			return utils.ToFloat32(cvss.Search("metrics", "baseScore").Data())
		case "3.0", "3.1":
			return utils.ToFloat32(cvss.Search("metrics", "baseScore").Data())
		}
	}

	return 0
}
