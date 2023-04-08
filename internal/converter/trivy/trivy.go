package trivy

import (
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vimp/internal/parser"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

// Convert converts JSON to a list of common vulnerabilities.
func Convert(c *gabs.Container) ([]*data.Vulnerability, error) {
	if c == nil {
		return nil, errors.New("source required")
	}

	list := make([]*data.Vulnerability, 0)

	for _, r := range c.Search("Results").Children() {
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

func mapVulnerability(v *gabs.Container) *data.Vulnerability {
	c := v.Search("CVSS")
	if !c.Exists() {
		return nil
	}

	item := &data.Vulnerability{
		Exposure: parser.String(v, "VulnerabilityID"),
		Package:  parser.String(v, "PkgName"),
		Version:  parser.String(v, "InstalledVersion"),
		Severity: strings.ToLower(parser.String(v, "Severity")),
		Score:    getScore(c, parser.String(v, "SeveritySource"), "nvd", "redhat"),
		IsFixed:  false, // trivy does not provide this info
	}

	return item
}

func getScore(v *gabs.Container, sources ...string) float32 {
	for _, s := range sources {
		c := v.Search(s)
		if c.Exists() {
			if c.Search("V3Score").Exists() {
				return parser.ToFloat32(c.Search("V3Score").Data())
			}
			if c.Search("V2Score").Exists() {
				return parser.ToFloat32(c.Search("V2Score").Data())
			}
		}
	}

	return 0
}
