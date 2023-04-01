package grype

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

	m := s.Data.Search("matches")
	if !m.Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make([]*vulnerability.Item, 0)

	for _, c := range m.Children() {
		vul := mapVulnerability(c)
		if vul == nil {
			continue
		}

		list = append(list, vul)
	}

	return list, nil
}

func mapVulnerability(m *gabs.Container) *vulnerability.Item {
	v := m.Search("vulnerability")
	if !v.Exists() {
		return nil
	}

	a := m.Search("artifact")
	if !a.Exists() {
		return nil
	}

	item := &vulnerability.Item{
		ID:       util.ToString(v.Search("id").Data()),
		Package:  util.ToString(a.Search("name").Data()),
		Version:  util.ToString(a.Search("version").Data()),
		Severity: strings.ToLower(util.ToString(v.Search("severity").Data())),
		Score:    getScore(m),
		IsFixed:  util.ToString(v.Search("fix", "state").Data()) == "fixed",
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
			return util.ToFloat32(cvss.Search("metrics", "baseScore").Data())
		case "3.0", "3.1":
			return util.ToFloat32(cvss.Search("metrics", "baseScore").Data())
		}
	}

	return 0
}
