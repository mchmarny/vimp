package data

import "time"

// DecorateVulnerabilities decorates a list of vulnerabilities with image and digest.
func DecorateVulnerabilities(list []*Vulnerability, image, digest string) []*ImageVulnerability {
	result := make([]*ImageVulnerability, 0, len(list))
	for _, v := range list {
		result = append(result, &ImageVulnerability{
			Vulnerability: v,
			Image:         image,
			Digest:        digest,
			ProcessedAt:   time.Now().UTC(),
		})
	}
	return result
}

// ImageVulnerability represents a single vulnerability.
type ImageVulnerability struct {
	*Vulnerability

	// Image is the image name.
	Image string `json:"image"`

	// Digest is the image digest.
	Digest string `json:"digest"`

	// ProcessedAt is the time the vulnerability was processed.
	ProcessedAt time.Time `json:"processed_at"`
}
