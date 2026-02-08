package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scanType ScanType
		want     string
	}{
		{AllScans, "all"},
		{Grype, "grype"},
		{Snyk, "snyk"},
		{Trivy, "trivy"},
		{OSV, "osv"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			got := tc.scanType.String()
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseScan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		want    ScanType
		wantErr bool
	}{
		{"grype", Grype, false},
		{"snyk", Snyk, false},
		{"trivy", Trivy, false},
		{"osv", OSV, false},
		{"invalid", AllScans, true},
		{"", AllScans, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := ParseScan(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseScans(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    []ScanType
		wantErr bool
	}{
		{"empty returns all", "", allScanners, false},
		{"all returns all", "all", allScanners, false},
		{"single grype", "grype", []ScanType{Grype}, false},
		{"single trivy", "trivy", []ScanType{Trivy}, false},
		{"multiple", "grype,trivy", []ScanType{Grype, Trivy}, false},
		{"with osv", "grype,osv", []ScanType{Grype, OSV}, false},
		{"invalid", "invalid", nil, true},
		{"partial invalid", "grype,invalid", nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseScans(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestOptionsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{
			name:    "valid with image",
			opts:    Options{Image: "docker.io/redis"},
			wantErr: false,
		},
		{
			name:    "valid with scans",
			opts:    Options{Image: "docker.io/redis", Scans: "grype"},
			wantErr: false,
		},
		{
			name:    "missing image",
			opts:    Options{},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.opts.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOptionsValidateSetsDefaultScans(t *testing.T) {
	t.Parallel()

	opts := Options{Image: "docker.io/redis"}
	err := opts.Validate()

	assert.NoError(t, err)
	assert.Equal(t, "all", opts.Scans)
}
