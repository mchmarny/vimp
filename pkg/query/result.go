package query

import (
	"crypto/sha256"
	"fmt"
	"time"
)

type ImageResult struct {
	// Versions represents the different versions of the image.
	Versions map[string]*DigestSummaryResult `json:"versions"`
}

type DigestSummaryResult struct {
	// Exposures is the number of exposures for that image digest.
	Exposures int `json:"exposures"`

	// Sources is the number of sources for that image digest.
	Sources int `json:"sources"`

	// Packages is the number of packages for that image digest.
	Packages int `json:"packages"`

	// HighScore is the highest score for that image digest.
	HighScore float32 `json:"high_score"`

	// First is the first time the image was discovered.
	First time.Time `json:"first_discovered"`

	// Last is the last time the image was discovered.
	Last time.Time `json:"last_discovered"`
}

type ImageExposureResult struct {
	// Image is the image result.
	Image string `json:"image"`

	// Digest is the image digest.
	Digest string `json:"digest"`

	// Exposures is the list of exposures.
	Exposures map[string][]*ExposureResult `json:"exposures"`
}

// HasUniqueExposures returns true if the image has unique exposures.
func HasUniqueExposures(list []*ExposureResult) bool {
	if len(list) == 0 {
		return false
	}

	var last *ExposureResult
	for _, x := range list {
		if last != nil && last.GetID() != x.GetID() {
			return true
		}
	}

	return false
}

type ExposureResult struct {
	// Source is the source of the vulnerability.
	Source string `json:"source"`

	// Severity is the vulnerability severity.
	Severity string `json:"severity,omitempty"`

	// Score is the vulnerability score.
	Score float32 `json:"score,omitempty"`

	// Last is the last time the image was discovered.
	Last time.Time `json:"last_discovered"`
}

func (e *ExposureResult) GetID() string {
	s := fmt.Sprintf("%s%s%f", e.Source, e.Severity, e.Score)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}

type PackageExposureResult struct {
	// Image is the image result.
	Image string `json:"image"`

	// Digest is the image digest.
	Digest string `json:"digest"`

	// Exposure is the exposure.
	Exposure string `json:"exposure"`

	// Packages is the list of packages.
	Packages []*PackageResult `json:"packages"`
}

type PackageResult struct {
	// Source is the source of the vulnerability.
	Source string `json:"source"`

	// Package is the package name.
	Package string `json:"package"`

	// Version is the package version.
	Version string `json:"version"`

	// Severity is the vulnerability severity.
	Severity string `json:"severity,omitempty"`

	// Score is the vulnerability score.
	Score float32 `json:"score,omitempty"`

	// Last is the last time the image was discovered.
	Last time.Time `json:"last_discovered"`
}
