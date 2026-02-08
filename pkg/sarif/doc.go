// Package sarif provides SARIF 2.1.0 output format for vulnerability reports.
//
// SARIF (Static Analysis Results Interchange Format) is an OASIS standard
// supported by GitHub Code Scanning and other security tools.
//
// The package provides:
//   - Report: top-level SARIF document structure
//   - FromVulnerabilities: converts vimp vulnerabilities to SARIF format
//
// Severity mapping:
//   - critical, high -> error
//   - medium -> warning
//   - low, negligible -> note
//
// Example usage:
//
//	report := sarif.FromVulnerabilities(vulns, "vimp", "1.0.0")
//	data, _ := json.MarshalIndent(report, "", "  ")
//	fmt.Println(string(data))
//
// Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
package sarif
