package trivy

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

	list := make([]*data.Vulnerability, 0)

	for _, r := range s.Search("Results").Children() {
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
		ID:       parser.ToString(v.Search("VulnerabilityID").Data()),
		Package:  parser.ToString(v.Search("PkgName").Data()),
		Version:  parser.ToString(v.Search("InstalledVersion").Data()),
		Severity: strings.ToLower(parser.ToString(v.Search("Severity").Data())),
		Score:    getScore(c),
		IsFixed:  false, // trivy does not provide this info
	}

	return item
}

func getScore(v *gabs.Container) float32 {
	c := v.Search("nvd")
	if c.Exists() {
		if c.Search("V2Score").Exists() {
			return parser.ToFloat32(c.Search("V2Score").Data())
		}
		if c.Search("V3Score").Exists() {
			return parser.ToFloat32(c.Search("V3Score").Data())
		}
	}

	c = v.Search("redhat")
	if c.Exists() {
		if c.Search("V2Score").Exists() {
			return parser.ToFloat32(c.Search("V2Score").Data())
		}
		if c.Search("V3Score").Exists() {
			return parser.ToFloat32(c.Search("V3Score").Data())
		}
	}

	return 0
}
