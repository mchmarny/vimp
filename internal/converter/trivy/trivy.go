package trivy

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

	for _, r := range s.Data.Search("Results").Children() {
		for _, v := range r.Search("Vulnerabilities").Children() {
			vul := mapVulnerability(v)
			if vul == nil {
				continue
			}

			list = append(list, vul)
		}
	}

	return list, nil
}

func mapVulnerability(v *gabs.Container) *vulnerability.Item {
	c := v.Search("CVSS")
	if !c.Exists() {
		return nil
	}

	item := &vulnerability.Item{
		ID:       util.ToString(v.Search("VulnerabilityID").Data()),
		Package:  util.ToString(v.Search("PkgName").Data()),
		Version:  util.ToString(v.Search("InstalledVersion").Data()),
		Severity: strings.ToLower(util.ToString(v.Search("Severity").Data())),
		Score:    getScore(c),
		IsFixed:  false, // trivy does not provide this info
	}

	return item
}

func getScore(v *gabs.Container) float32 {
	c := v.Search("nvd")
	if c.Exists() {
		if c.Search("V2Score").Exists() {
			return util.ToFloat32(c.Search("V2Score").Data())
		}
		if c.Search("V3Score").Exists() {
			return util.ToFloat32(c.Search("V3Score").Data())
		}
	}

	c = v.Search("redhat")
	if c.Exists() {
		if c.Search("V2Score").Exists() {
			return util.ToFloat32(c.Search("V2Score").Data())
		}
		if c.Search("V3Score").Exists() {
			return util.ToFloat32(c.Search("V3Score").Data())
		}
	}

	return 0
}
