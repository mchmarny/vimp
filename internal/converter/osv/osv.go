package osv

import (
	"context"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vimp/internal/parser"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

const Name = "osv"

// Converter implements the converter.Converter interface for OSV-Scanner output.
type Converter struct{}

// New creates a new OSV-Scanner converter.
func New() *Converter {
	return &Converter{}
}

// Name returns the converter identifier.
func (o *Converter) Name() string {
	return Name
}

// CanHandle returns true if the JSON container is OSV-Scanner output.
// OSV-Scanner output has results[] with packages[] containing ecosystem info.
func (o *Converter) CanHandle(c *gabs.Container) bool {
	if c == nil {
		return false
	}
	if !c.ExistsP("results") {
		return false
	}

	// Check if results contains packages with ecosystem
	results := c.Search("results")
	if results.Data() == nil {
		return false
	}
	for _, r := range results.Children() {
		packages := r.Search("packages")
		if packages.Exists() {
			for _, pkg := range packages.Children() {
				if pkg.ExistsP("package.ecosystem") {
					return true
				}
			}
		}
	}
	return false
}

// Convert transforms OSV-Scanner JSON output into normalized vulnerabilities.
func (o *Converter) Convert(ctx context.Context, c *gabs.Container) ([]*data.Vulnerability, error) {
	return Convert(ctx, c)
}

// Convert converts OSV-Scanner JSON to a list of common vulnerabilities.
func Convert(ctx context.Context, c *gabs.Container) ([]*data.Vulnerability, error) {
	if c == nil {
		return nil, errors.New("source required")
	}

	results := c.Search("results")
	if !results.Exists() {
		return nil, errors.New("unable to find results in source data")
	}

	list := make([]*data.Vulnerability, 0)

	// results[] -> packages[] -> vulnerabilities[]
	for _, result := range results.Children() {
		packages := result.Search("packages")
		if !packages.Exists() {
			continue
		}

		for _, pkg := range packages.Children() {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			pkgInfo := pkg.Search("package")
			pkgName := parser.String(pkgInfo, "name")
			pkgVersion := parser.String(pkgInfo, "version")

			vulns := pkg.Search("vulnerabilities")
			if !vulns.Exists() {
				continue
			}

			for _, v := range vulns.Children() {
				vul := mapVulnerability(v, pkgName, pkgVersion)
				if vul == nil {
					continue
				}
				list = append(list, vul)
			}
		}
	}

	return list, nil
}

func mapVulnerability(v *gabs.Container, pkgName, pkgVersion string) *data.Vulnerability {
	// Get exposure ID - prefer CVE from aliases, fallback to vuln id
	exposure := getExposureID(v)
	if exposure == "" {
		return nil
	}

	// Check if there's a fixed version
	hasFixed := hasFixedVersion(v)

	item := &data.Vulnerability{
		Exposure: exposure,
		Package:  pkgName,
		Version:  pkgVersion,
		Severity: "unknown", // OSV-Scanner doesn't provide severity in JSON
		Score:    0,         // OSV-Scanner doesn't provide CVSS scores in JSON
		IsFixed:  hasFixed,
	}

	return item
}

// getExposureID extracts the best exposure ID from aliases, preferring CVE IDs.
func getExposureID(v *gabs.Container) string {
	// Check aliases first for CVE
	aliases := v.Search("aliases")
	if aliases.Exists() {
		for _, alias := range aliases.Children() {
			id := parser.ToString(alias.Data())
			if strings.HasPrefix(id, "CVE-") {
				return id
			}
		}
		// If no CVE, return first alias
		if first := aliases.Index(0); first.Data() != nil {
			return parser.ToString(first.Data())
		}
	}

	// Fallback to the main id
	return parser.String(v, "id")
}

// hasFixedVersion checks if any affected range has a fixed version.
func hasFixedVersion(v *gabs.Container) bool {
	affected := v.Search("affected")
	if !affected.Exists() {
		return false
	}

	for _, a := range affected.Children() {
		ranges := a.Search("ranges")
		if !ranges.Exists() {
			continue
		}
		for _, r := range ranges.Children() {
			events := r.Search("events")
			if !events.Exists() {
				continue
			}
			for _, event := range events.Children() {
				if event.ExistsP("fixed") {
					return true
				}
			}
		}
	}
	return false
}
