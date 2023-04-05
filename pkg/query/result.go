package query

import (
	"time"
)

type Image struct {
	// Image is the image name.
	Image string `json:"image"`

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

// Equal returns true if the vulnerability sources are equal.
func (v *VulnerabilitySource) Equal(other *VulnerabilitySource) bool {
	return v.Source == other.Source &&
		v.Severity == other.Severity &&
		v.Score == other.Score
}

func (v *VulnerabilitySource) String() string {
	return v.Source
}

// VulnerabilityList represents a list of vulnerabilities.
type VulnerabilityList struct {
	Image           *Image                            `json:"image"`
	Count           int                               `json:"count"`
	Vulnerabilities map[string][]*VulnerabilitySource `json:"vulnerabilities,omitempty"`
}

// FilterOutDuplicates removes duplicate vulnerabilities.
func FilterOutDuplicates(in map[string][]*VulnerabilitySource) map[string][]*VulnerabilitySource {
	out := make(map[string][]*VulnerabilitySource)
	for cve, v := range in {
		if areDiff(v) {
			out[cve] = v
		}
	}
	return out
}

func areDiff(vuls []*VulnerabilitySource) bool {
	var last *VulnerabilitySource
	for _, v := range vuls {
		if last == nil {
			last = v
			continue
		}

		if !last.Equal(v) {
			return true
		}
	}
	return false
}
