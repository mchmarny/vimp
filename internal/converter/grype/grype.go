package grype

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

	m := s.Search("matches")
	if !m.Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make([]*data.Vulnerability, 0)

	for _, c := range m.Children() {
		vul := mapVulnerability(c)
		if vul == nil {
			continue
		}

		list = append(list, vul)
	}

	return list, nil
}

func mapVulnerability(m *gabs.Container) *data.Vulnerability {
	v := m.Search("vulnerability")
	if !v.Exists() {
		return nil
	}

	a := m.Search("artifact")
	if !a.Exists() {
		return nil
	}

	item := &data.Vulnerability{
		ID:       parser.ToString(v.Search("id").Data()),
		Package:  parser.ToString(a.Search("name").Data()),
		Version:  parser.ToString(a.Search("version").Data()),
		Severity: strings.ToLower(parser.ToString(v.Search("severity").Data())),
		Score:    getScore(m),
		IsFixed:  parser.ToString(v.Search("fix", "state").Data()) == "fixed",
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
			return parser.ToFloat32(cvss.Search("metrics", "baseScore").Data())
		case "3.0", "3.1":
			return parser.ToFloat32(cvss.Search("metrics", "baseScore").Data())
		}
	}

	return 0
}
