// Package cmd provides CLI commands for vimp.
//
// Commands:
//   - import: import vulnerability data from scanner output or auto-scan
//   - query: query stored vulnerability data
//
// Import supports:
//   - File import: vimp import --source <image> --file <report.json>
//   - Auto-scan: vimp import --source <image> (uses installed scanners)
//
// Query supports:
//   - Image summary: vimp query
//   - Digest list: vimp query --image <image>
//   - Exposures: vimp query --image <image> --digest <digest>
//   - Packages: vimp query --image <image> --digest <digest> --exposure <cve>
//   - SARIF output: vimp query --format sarif
//
// Target URIs:
//   - sqlite://path/to/db.db (default: ~/.vimp.db)
//   - postgres://host:port/db
//   - bq://project.dataset.table
//   - file://path/to/output.json
//   - console://
package cmd
