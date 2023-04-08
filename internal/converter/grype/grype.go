package grype

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

	m := c.Search("matches")
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

	rv := m.Search("relatedVulnerabilities").Index(0)

	item := &data.Vulnerability{
		Exposure: parser.ToString(parser.FirstNonEmpty(
			rv.Search("id").Data(),
			v.Search("id").Data())),
		Package: parser.String(a, "name"),
		Version: parser.String(a, "version"),
		Severity: strings.ToLower(parser.FirstNonEmpty(
			rv.Search("severity").Data(),
			v.Search("severity").Data())),
		Score:   getScore(rv.Search("cvss")),
		IsFixed: parser.ToString(v.Search("fix", "state").Data()) == "fixed",
	}

	return item
}

func getScore(v *gabs.Container) float32 {
	if !v.Exists() {
		return 0
	}

	v2 := float32(0.0)
	v3 := float32(0.0)

	for _, cvss := range v.Children() {
		switch cvss.Search("version").Data().(string) {
		case "2.0":
			v2 = parser.ToFloat32(cvss.Search("metrics", "baseScore").Data())
		case "3.0", "3.1":
			v3 = parser.ToFloat32(cvss.Search("metrics", "baseScore").Data())
		}
	}

	if v3 > 0 {
		return v3
	}

	return v2
}
