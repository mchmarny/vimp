package clair

import (
	"context"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vimp/internal/parser"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

const Name = "clair"

// Converter implements the converter.Converter interface for Clair scanner output.
type Converter struct{}

// New creates a new Clair converter.
func New() *Converter {
	return &Converter{}
}

// Name returns the converter identifier.
func (c *Converter) Name() string {
	return Name
}

// CanHandle returns true if the JSON container is Clair output.
// Clair v4 output has manifest_hash and vulnerabilities at the top level.
func (c *Converter) CanHandle(container *gabs.Container) bool {
	if container == nil {
		return false
	}
	return container.ExistsP("manifest_hash") && container.ExistsP("vulnerabilities")
}

// Convert transforms Clair JSON output into normalized vulnerabilities.
func (c *Converter) Convert(ctx context.Context, container *gabs.Container) ([]*data.Vulnerability, error) {
	return Convert(ctx, container)
}

// Convert converts Clair JSON to a list of common vulnerabilities.
func Convert(ctx context.Context, c *gabs.Container) ([]*data.Vulnerability, error) {
	if c == nil {
		return nil, errors.New("source required")
	}

	vulns := c.Search("vulnerabilities")
	if !vulns.Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make([]*data.Vulnerability, 0)

	// Clair vulnerabilities is a map of vuln_id -> vulnerability object
	vulnMap, ok := vulns.Data().(map[string]interface{})
	if !ok {
		return nil, errors.New("vulnerabilities is not a map")
	}

	for _, v := range vulnMap {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		vulnData, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		vulnContainer := gabs.Wrap(vulnData)
		vul := mapVulnerability(vulnContainer)
		if vul == nil {
			continue
		}

		list = append(list, vul)
	}

	return list, nil
}

func mapVulnerability(v *gabs.Container) *data.Vulnerability {
	name := parser.String(v, "name")
	if name == "" {
		return nil
	}

	// Get package info from the embedded package object
	pkg := v.Search("package")
	if !pkg.Exists() {
		return nil
	}

	item := &data.Vulnerability{
		Exposure: name,
		Package:  parser.String(pkg, "name"),
		Version:  parser.String(pkg, "version"),
		Severity: strings.ToLower(parser.String(v, "normalized_severity")),
		Score:    0, // Clair does not provide CVSS scores
		IsFixed:  parser.String(v, "fixed_in_version") != "",
	}

	// Fallback to Unknown severity if not provided
	if item.Severity == "" {
		item.Severity = "unknown"
	}

	return item
}
