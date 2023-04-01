package types

// Vulnerability represents a vulnerability.
type Vulnerability struct {
	// ID is the vulnerability ID.
	ID string `json:"id"`

	// Package is the package name.
	Package string `json:"package"`

	// Version is the package version.
	Version string `json:"version"`

	// Severity is the vulnerability severity.
	Severity string `json:"severity"`

	// Score is the vulnerability score.
	Score float32 `json:"score"`

	// Is Fixed indicates of the vulnerability has been fixed.
	IsFixed bool `json:"fixed"`
}
