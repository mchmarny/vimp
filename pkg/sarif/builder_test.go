package sarif

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/stretchr/testify/assert"
)

func TestFromVulnerabilities(t *testing.T) {
	vuls := []*data.ImageVulnerability{
		{
			Image:       "alpine:latest",
			Digest:      "sha256:abc123",
			Source:      "grype",
			ProcessedAt: time.Now(),
			Vulnerability: &data.Vulnerability{
				Exposure: "CVE-2021-3711",
				Package:  "openssl",
				Version:  "1.1.1k",
				Severity: "critical",
				Score:    9.8,
				IsFixed:  true,
			},
		},
		{
			Image:       "alpine:latest",
			Digest:      "sha256:abc123",
			Source:      "grype",
			ProcessedAt: time.Now(),
			Vulnerability: &data.Vulnerability{
				Exposure: "CVE-2021-22945",
				Package:  "curl",
				Version:  "7.79.1",
				Severity: "medium",
				Score:    7.5,
				IsFixed:  false,
			},
		},
	}

	report := FromVulnerabilities(vuls, "vimp", "1.0.0")

	assert.NotNil(t, report)
	assert.Equal(t, Version, report.Version)
	assert.Equal(t, SchemaURI, report.Schema)
	assert.Len(t, report.Runs, 1)

	run := report.Runs[0]
	assert.Equal(t, "vimp", run.Tool.Driver.Name)
	assert.Equal(t, "1.0.0", run.Tool.Driver.Version)
	assert.Len(t, run.Tool.Driver.Rules, 2)
	assert.Len(t, run.Results, 2)

	// Check levels
	for _, result := range run.Results {
		switch result.RuleID {
		case "CVE-2021-3711":
			assert.Equal(t, "error", result.Level)
		case "CVE-2021-22945":
			assert.Equal(t, "warning", result.Level)
		}
	}
}

func TestMapSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		level    string
	}{
		{"critical", "error"},
		{"CRITICAL", "error"},
		{"high", "error"},
		{"HIGH", "error"},
		{"medium", "warning"},
		{"MEDIUM", "warning"},
		{"low", "note"},
		{"LOW", "note"},
		{"negligible", "note"},
		{"unknown", "warning"},
		{"", "warning"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			assert.Equal(t, tt.level, mapSeverityToLevel(tt.severity))
		})
	}
}

func TestSARIFJSONOutput(t *testing.T) {
	vuls := []*data.ImageVulnerability{
		{
			Image:       "alpine:latest",
			Digest:      "sha256:abc123",
			Source:      "trivy",
			ProcessedAt: time.Now(),
			Vulnerability: &data.Vulnerability{
				Exposure: "CVE-2021-3711",
				Package:  "openssl",
				Version:  "1.1.1k",
				Severity: "high",
				Score:    9.8,
				IsFixed:  true,
			},
		},
	}

	report := FromVulnerabilities(vuls, "vimp", "1.0.0")

	// Ensure it can be marshaled to valid JSON
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonBytes)

	// Verify it can be unmarshaled back
	var parsed Report
	err = json.Unmarshal(jsonBytes, &parsed)
	assert.NoError(t, err)
	assert.Equal(t, Version, parsed.Version)
}
