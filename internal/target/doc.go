// Package target provides storage backends for vulnerability data.
//
// Targets are selected by URI scheme:
//   - sqlite://path/to/db.db - SQLite database (default, supports query)
//   - postgres://host:port/db - PostgreSQL database (supports query)
//   - bq://project.dataset.table - Google BigQuery (import only)
//   - file://path/to/output.json - JSON file output
//   - console:// - stdout output
//
// Import targets store vulnerabilities:
//
//	importer, _ := target.GetImporter("sqlite://vulns.db")
//	err := importer(ctx, uri, vulnerabilities)
//
// Query targets support data retrieval:
//
//	querier, _ := target.GetQuerier("sqlite://vulns.db")
//	result, err := querier(ctx, &query.Options{Image: "redis"})
//
// Database schema uses a 6-part primary key for deduplication:
// (image, digest, source, exposure, package, version)
package target
