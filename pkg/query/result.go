package query

import (
	"time"
)

type Image struct {
	// URI is the image name.
	URI string `json:"uri"`

	// Digest is the image digest.
	Digest string `json:"digest,omitempty"`
}

type VulnerabilitySource struct {
	// Source is the source of the vulnerability.
	Source string `json:"source"`

	// Severity is the vulnerability severity.
	Severity string `json:"severity,omitempty"`

	// Score is the vulnerability score.
	Score float32 `json:"score,omitempty"`

	// Is Fixed indicates of the vulnerability has been fixed.
	IsFixed bool `json:"fixed,omitempty"`

	// ProcessedAt is the time the vulnerability was processed.
	ProcessedAt time.Time `json:"processed_at"`
}

// VulnerabilityList represents a list of vulnerabilities.
type VulnerabilityList struct {
	Image           *Image                            `json:"image"`
	Vulnerabilities map[string][]*VulnerabilitySource `json:"vulnerabilities,omitempty"`
}
