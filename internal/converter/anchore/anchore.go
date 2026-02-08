package anchore

import (
	"context"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vimp/internal/parser"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

const Name = "anchore"

// Converter implements the converter.Converter interface for Anchore Engine output.
type Converter struct{}

// New creates a new Anchore converter.
func New() *Converter {
	return &Converter{}
}

// Name returns the converter identifier.
func (a *Converter) Name() string {
	return Name
}

// CanHandle returns true if the JSON container is Anchore Engine output.
// Anchore output has imageDigest and vulnerabilities at the top level.
func (a *Converter) CanHandle(c *gabs.Container) bool {
	if c == nil {
		return false
	}
	return c.ExistsP("imageDigest") && c.ExistsP("vulnerabilities")
}

// Convert transforms Anchore Engine JSON output into normalized vulnerabilities.
func (a *Converter) Convert(ctx context.Context, c *gabs.Container) ([]*data.Vulnerability, error) {
	return Convert(ctx, c)
}

// Convert converts Anchore Engine JSON to a list of common vulnerabilities.
func Convert(ctx context.Context, c *gabs.Container) ([]*data.Vulnerability, error) {
	if c == nil {
		return nil, errors.New("source required")
	}

	vulns := c.Search("vulnerabilities")
	if !vulns.Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make([]*data.Vulnerability, 0)

	for _, v := range vulns.Children() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		vul := mapVulnerability(v)
		if vul == nil {
			continue
		}

		list = append(list, vul)
	}

	return list, nil
}

func mapVulnerability(v *gabs.Container) *data.Vulnerability {
	exposure := parser.String(v, "vuln")
	if exposure == "" {
		return nil
	}

	item := &data.Vulnerability{
		Exposure: exposure,
		Package:  parser.GetFirstString(v, "package_name", "package"),
		Version:  parser.GetFirstString(v, "package_version", "package"),
		Severity: strings.ToLower(parser.String(v, "severity")),
		Score:    getScore(v),
		IsFixed:  parser.String(v, "fix") != "" && parser.String(v, "fix") != "None",
	}

	// Fallback to Unknown severity if not provided
	if item.Severity == "" {
		item.Severity = "unknown"
	}

	return item
}

// getScore extracts the CVSS score from nvd_data, preferring v3 over v2.
func getScore(v *gabs.Container) float32 {
	nvdData := v.Search("nvd_data")
	if !nvdData.Exists() {
		return 0
	}

	// nvd_data is an array, usually with one element
	for _, nvd := range nvdData.Children() {
		// Prefer CVSS v3
		if v3 := nvd.Search("cvss_v3", "base_score"); v3.Exists() {
			return parser.ToFloat32(v3.Data())
		}
		// Fallback to CVSS v2
		if v2 := nvd.Search("cvss_v2", "base_score"); v2.Exists() {
			return parser.ToFloat32(v2.Data())
		}
	}

	return 0
}
