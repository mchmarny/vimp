package grype

import (
	"context"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vimp/internal/parser"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

const Name = "grype"

// Converter implements the converter.Converter interface for Grype scanner output.
type Converter struct{}

// New creates a new Grype converter.
func New() *Converter {
	return &Converter{}
}

// Name returns the converter identifier.
func (g *Converter) Name() string {
	return Name
}

// CanHandle returns true if the JSON container is Grype output.
func (g *Converter) CanHandle(c *gabs.Container) bool {
	if c == nil {
		return false
	}
	d := c.Search("descriptor", "name")
	return d.Exists() && parser.ToString(d.Data()) == "grype"
}

// Convert transforms Grype JSON output into normalized vulnerabilities.
func (g *Converter) Convert(ctx context.Context, c *gabs.Container) ([]*data.Vulnerability, error) {
	return Convert(ctx, c)
}

// Convert converts JSON to a list of common vulnerabilities.
func Convert(ctx context.Context, c *gabs.Container) ([]*data.Vulnerability, error) {
	if c == nil {
		return nil, errors.New("source required")
	}

	m := c.Search("matches")
	if !m.Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make([]*data.Vulnerability, 0)

	for _, child := range m.Children() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		vul := mapVulnerability(child)
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
