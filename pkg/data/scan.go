package data

import "time"

// Scan represents a vulnerability scan.
type Scan struct {
	URI             string           `json:"uri"`
	Digest          string           `json:"digest"`
	PerformedAt     time.Time        `json:"performed_at"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	Count           int              `json:"count"`
}
