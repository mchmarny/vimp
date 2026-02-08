// Package processor orchestrates the import and query workflows.
//
// Import workflow:
//  1. Parse scanner JSON output
//  2. Auto-detect scanner format via converter registry
//  3. Convert to normalized Vulnerability structures
//  4. Deduplicate by SHA256 hash of exposure+package+version
//  5. Store via target importer
//
// Query workflow:
//  1. Validate query options
//  2. Determine query type (images, digests, exposure, packages, etc.)
//  3. Execute via target querier
//  4. Format output (JSON or SARIF)
//
// Example import:
//
//	opts := &processor.ImportOptions{
//	    Source: "docker.io/redis:latest",
//	    File:   "grype-output.json",
//	    Target: "sqlite://vulns.db",
//	}
//	err := processor.Import(ctx, opts)
//
// Example query:
//
//	opts := &query.Options{
//	    Image:  "docker.io/redis",
//	    Target: "sqlite://vulns.db",
//	    Format: query.FormatJSON,
//	}
//	result, err := processor.QueryWithContext(ctx, opts)
package processor
