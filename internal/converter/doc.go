// Package converter provides pluggable parsers for vulnerability scanner output.
//
// Each scanner produces JSON in a unique format. Converters normalize this
// output into a common Vulnerability structure for unified storage and querying.
//
// Supported scanners:
//   - grype: Anchore Grype scanner
//   - trivy: Aqua Security Trivy scanner
//   - snyk: Snyk Container scanner
//   - clair: CoreOS Clair scanner
//   - osv: Google OSV-Scanner
//   - anchore: Anchore Engine (legacy)
//
// The Registry pattern enables auto-detection of scanner format:
//
//	registry := converter.DefaultRegistry()
//	conv, err := registry.Detect(jsonContainer)
//	if err != nil {
//	    // unknown format
//	}
//	vulns, err := conv.Convert(ctx, jsonContainer)
//
// To add a new scanner, implement the Converter interface:
//
//	type Converter interface {
//	    Name() string
//	    CanHandle(c *gabs.Container) bool
//	    Convert(ctx context.Context, c *gabs.Container) ([]*data.Vulnerability, error)
//	}
package converter
