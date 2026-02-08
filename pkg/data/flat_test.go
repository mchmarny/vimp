package data

import (
	"testing"
	"time"
)

func TestDecorateVulnerabilities(t *testing.T) {
	t.Parallel()

	vulns := []*Vulnerability{
		{
			Exposure: "CVE-2021-44228",
			Package:  "log4j-core",
			Version:  "2.14.1",
			Severity: "critical",
			Score:    10.0,
			IsFixed:  false,
		},
		{
			Exposure: "CVE-2021-45046",
			Package:  "log4j-core",
			Version:  "2.14.1",
			Severity: "high",
			Score:    9.0,
			IsFixed:  true,
		},
	}

	image := "docker.io/redis"
	digest := "sha256:abc123"
	source := "grype"

	result := DecorateVulnerabilities(vulns, image, digest, source)

	if len(result) != len(vulns) {
		t.Errorf("DecorateVulnerabilities() returned %d items, want %d", len(result), len(vulns))
	}

	for i, iv := range result {
		if iv.Image != image {
			t.Errorf("result[%d].Image = %s, want %s", i, iv.Image, image)
		}
		if iv.Digest != digest {
			t.Errorf("result[%d].Digest = %s, want %s", i, iv.Digest, digest)
		}
		if iv.Source != source {
			t.Errorf("result[%d].Source = %s, want %s", i, iv.Source, source)
		}
		if iv.ProcessedAt.IsZero() {
			t.Errorf("result[%d].ProcessedAt should not be zero", i)
		}
		if iv.Vulnerability != vulns[i] {
			t.Errorf("result[%d].Vulnerability pointer mismatch", i)
		}
	}
}

func TestDecorateVulnerabilitiesEmpty(t *testing.T) {
	t.Parallel()

	result := DecorateVulnerabilities([]*Vulnerability{}, "image", "digest", "source")

	if len(result) != 0 {
		t.Errorf("DecorateVulnerabilities() with empty input returned %d items", len(result))
	}
}

func TestImageVulnerabilityStrings(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	iv := &ImageVulnerability{
		Vulnerability: &Vulnerability{
			Exposure: "CVE-2021-44228",
			Package:  "log4j-core",
			Version:  "2.14.1",
			Severity: "critical",
			Score:    10.0,
			IsFixed:  false,
		},
		Image:       "docker.io/redis",
		Digest:      "sha256:abc123",
		Source:      "grype",
		ProcessedAt: now,
	}

	strs := iv.Strings()

	// Should return 10 fields
	if len(strs) != 10 {
		t.Errorf("Strings() returned %d items, want 10", len(strs))
	}

	// Check specific fields
	expected := []string{
		"docker.io/redis",
		"sha256:abc123",
		"grype",
		now.Format(time.RFC3339),
		"CVE-2021-44228",
		"log4j-core",
		"2.14.1",
		"critical",
	}

	for i, want := range expected {
		if strs[i] != want {
			t.Errorf("Strings()[%d] = %s, want %s", i, strs[i], want)
		}
	}

	// Check score (index 8) contains the value
	if strs[8] == "" {
		t.Error("Strings()[8] (score) is empty")
	}

	// Check fixed (index 9)
	if strs[9] != "false" {
		t.Errorf("Strings()[9] = %s, want false", strs[9])
	}
}
