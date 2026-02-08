// Package config provides configuration utilities for vimp.
//
// Key functions:
//   - GetDefaultDBPath: returns default SQLite database path (~/.vimp.db)
//   - RemoveSchema: strips protocol scheme from image URIs
//   - GetTempFilePath: creates temporary file paths for scanner output
//
// Database configuration:
//
//	path := config.GetDefaultDBPath() // sqlite://~/.vimp.db
//
// Image URI handling:
//
//	// Removes docker:// or other scheme prefixes
//	image, _ := config.RemoveSchema("docker://redis:latest") // "redis:latest"
package config
