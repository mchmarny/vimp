package trivy

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

	for _, r := range s.Data.Search("Results").Children() {
		for _, v := range r.Search("Vulnerabilities").Children() {
			vul := mapVulnerability(v)
			if vul == nil {
				continue
			}

			list[vul.ID] = vul
		}
	}

	return list, nil
}

func mapVulnerability(v *gabs.Container) *types.Vulnerability {
	c := v.Search("CVSS")
	if !c.Exists() {
		return nil
	}

	item := &types.Vulnerability{
		ID:       utils.ToString(v.Search("VulnerabilityID").Data()),
		Package:  utils.ToString(v.Search("PkgName").Data()),
		Version:  utils.ToString(v.Search("InstalledVersion").Data()),
		Severity: strings.ToLower(utils.ToString(v.Search("Severity").Data())),
		Score:    getScore(c),
		IsFixed:  false, // trivy does not provide this info
	}

	return item
}

func getScore(v *gabs.Container) float32 {
	c := v.Search("nvd")
	if c.Exists() {
		if c.Search("V2Score").Exists() {
			return utils.ToFloat32(c.Search("V2Score").Data())
		}
		if c.Search("V3Score").Exists() {
			return utils.ToFloat32(c.Search("V3Score").Data())
		}
	}

	c = v.Search("redhat")
	if c.Exists() {
		if c.Search("V2Score").Exists() {
			return utils.ToFloat32(c.Search("V2Score").Data())
		}
		if c.Search("V3Score").Exists() {
			return utils.ToFloat32(c.Search("V3Score").Data())
		}
	}

	return 0
}
