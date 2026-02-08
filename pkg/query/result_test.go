package query

import (
	"testing"
	"time"
)

func TestHasUniqueExposureSeverityScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		list []*ExposureResult
		want bool
	}{
		{
			name: "empty list",
			list: []*ExposureResult{},
			want: false,
		},
		{
			name: "single item",
			list: []*ExposureResult{
				{Severity: "high", Score: 7.5},
			},
			want: false,
		},
		{
			name: "same severity and score",
			list: []*ExposureResult{
				{Source: "grype", Severity: "high", Score: 7.5},
				{Source: "trivy", Severity: "high", Score: 7.5},
			},
			want: false,
		},
		{
			name: "different severity",
			list: []*ExposureResult{
				{Source: "grype", Severity: "high", Score: 7.5},
				{Source: "trivy", Severity: "medium", Score: 7.5},
			},
			want: true,
		},
		{
			name: "different score",
			list: []*ExposureResult{
				{Source: "grype", Severity: "high", Score: 7.5},
				{Source: "trivy", Severity: "high", Score: 8.0},
			},
			want: true,
		},
		{
			name: "multiple sources different values",
			list: []*ExposureResult{
				{Source: "grype", Severity: "high", Score: 7.5},
				{Source: "trivy", Severity: "medium", Score: 5.0},
				{Source: "snyk", Severity: "low", Score: 3.3},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := HasUniqueExposureSeverityScore(tc.list)
			if got != tc.want {
				t.Errorf("HasUniqueExposureSeverityScore() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExposureResultGetSeverityScoreHash(t *testing.T) {
	t.Parallel()

	e1 := &ExposureResult{Severity: "high", Score: 7.5}
	e2 := &ExposureResult{Severity: "high", Score: 7.5}
	e3 := &ExposureResult{Severity: "medium", Score: 7.5}

	// Same severity and score should produce same hash
	hash1 := e1.GetSeverityScoreHash()
	hash2 := e2.GetSeverityScoreHash()
	if hash1 != hash2 {
		t.Errorf("Same values should produce same hash: %s != %s", hash1, hash2)
	}

	// Different severity should produce different hash
	hash3 := e3.GetSeverityScoreHash()
	if hash1 == hash3 {
		t.Errorf("Different severity should produce different hash: %s == %s", hash1, hash3)
	}

	// Hash should be 64 characters (SHA256 hex)
	if len(hash1) != 64 {
		t.Errorf("Hash should be 64 chars, got %d", len(hash1))
	}
}

func TestImageResult(t *testing.T) {
	t.Parallel()

	now := time.Now()
	result := &ImageResult{
		Versions: map[string]*DigestSummaryResult{
			"sha256:abc123": {
				Exposures: 10,
				Sources:   3,
				Packages:  5,
				HighScore: 9.8,
				First:     now.Add(-24 * time.Hour),
				Last:      now,
			},
		},
	}

	if len(result.Versions) != 1 {
		t.Errorf("Expected 1 version, got %d", len(result.Versions))
	}

	digest := result.Versions["sha256:abc123"]
	if digest == nil {
		t.Fatal("Expected digest to exist")
	}
	if digest.Exposures != 10 {
		t.Errorf("Exposures = %d, want 10", digest.Exposures)
	}
	if digest.HighScore != 9.8 {
		t.Errorf("HighScore = %f, want 9.8", digest.HighScore)
	}
}

func TestTimeSeriesResult(t *testing.T) {
	t.Parallel()

	result := &TimeSeriesResult{
		Image: "docker.io/redis",
		DataPoints: []*TimeSeriesDataPoint{
			{Date: "2024-01-01", Total: 100, Critical: 5, High: 20, Medium: 50, Low: 25},
			{Date: "2024-01-02", Total: 95, Critical: 4, High: 19, Medium: 48, Low: 24},
		},
	}

	if result.Image != "docker.io/redis" {
		t.Errorf("Image = %s, want docker.io/redis", result.Image)
	}
	if len(result.DataPoints) != 2 {
		t.Errorf("DataPoints length = %d, want 2", len(result.DataPoints))
	}
}

func TestCommonVulnsResult(t *testing.T) {
	t.Parallel()

	result := &CommonVulnsResult{
		Images: []string{"redis", "nginx"},
		Common: map[string]*CommonVulnInfo{
			"CVE-2021-44228": {
				Severity:       "critical",
				Score:          10.0,
				AffectedImages: []string{"redis", "nginx"},
			},
		},
	}

	if len(result.Images) != 2 {
		t.Errorf("Images length = %d, want 2", len(result.Images))
	}
	if len(result.Common) != 1 {
		t.Errorf("Common length = %d, want 1", len(result.Common))
	}

	vuln := result.Common["CVE-2021-44228"]
	if vuln == nil {
		t.Fatal("Expected vulnerability to exist")
	}
	if vuln.Severity != "critical" {
		t.Errorf("Severity = %s, want critical", vuln.Severity)
	}
}
