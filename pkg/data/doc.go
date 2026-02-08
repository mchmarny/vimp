// Package data provides core data structures for vulnerability representation.
//
// The package defines two main types:
//   - Vulnerability: normalized vulnerability information from any scanner
//   - ImageVulnerability: vulnerability with image context (digest, source, timestamp)
//
// Vulnerabilities are uniquely identified by a SHA256 hash of exposure+package+version,
// enabling deduplication across multiple scanner sources.
//
// Example usage:
//
//	vuln := &data.Vulnerability{
//	    Exposure: "CVE-2021-44228",
//	    Package:  "log4j-core",
//	    Version:  "2.14.1",
//	    Severity: "critical",
//	    Score:    10.0,
//	    IsFixed:  false,
//	}
//	id := vuln.GetID() // SHA256 hash for deduplication
package data
