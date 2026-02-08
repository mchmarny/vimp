// Package query provides types and utilities for querying vulnerability data.
//
// Query types support hierarchical exploration of stored vulnerabilities:
//   - Images: list all scanned images
//   - Digests: list all digests for an image
//   - Exposure: list vulnerabilities for an image/digest
//   - Packages: list packages affected by a specific CVE
//   - TimeSeries: vulnerability counts over time
//   - CommonVulns: CVEs shared across multiple images
//
// Output formats:
//   - FormatJSON: standard JSON output (default)
//   - FormatSARIF: SARIF 2.1.0 for GitHub Code Scanning integration
//
// Example usage:
//
//	opts := &query.Options{
//	    Image:  "docker.io/redis",
//	    Digest: "sha256:abc123...",
//	    Target: "sqlite://vulns.db",
//	    Format: query.FormatJSON,
//	}
//	if err := opts.Validate(); err != nil {
//	    // handle error
//	}
//	queryType, _ := opts.GetQuery() // auto-detects query type
package query
