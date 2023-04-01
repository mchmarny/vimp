package data

import "time"

// Scan represents a vulnerability scan.
type Scan struct {
	URI             string           `json:"uri"`
	Digest          string           `json:"digest"`
	ProcessedAt     time.Time        `json:"processed_at"`
	RecordCount     int              `json:"record_count"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
}
