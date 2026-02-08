package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegistry(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	assert.NotNil(t, r)
	assert.Empty(t, r.All())

	r.Register(NewGrypeScanner())
	assert.Len(t, r.All(), 1)

	names := r.Names()
	assert.Contains(t, names, "grype")
}

func TestDefaultRegistry(t *testing.T) {
	t.Parallel()

	r := DefaultRegistry()
	assert.NotNil(t, r)
	assert.Len(t, r.All(), 4) // grype, trivy, snyk, osv

	names := r.Names()
	assert.Contains(t, names, "grype")
	assert.Contains(t, names, "trivy")
	assert.Contains(t, names, "snyk")
	assert.Contains(t, names, "osv")
}

func TestRegistryGet(t *testing.T) {
	t.Parallel()

	r := DefaultRegistry()

	scanner, ok := r.Get("grype")
	assert.True(t, ok)
	assert.Equal(t, "grype", scanner.Name())

	scanner, ok = r.Get("nonexistent")
	assert.False(t, ok)
	assert.Nil(t, scanner)
}

func TestGetScanner(t *testing.T) {
	t.Parallel()

	scanner, ok := GetScanner("grype")
	assert.True(t, ok)
	assert.Equal(t, "grype", scanner.Name())
	assert.Equal(t, "grype", scanner.ConverterName())

	scanner, ok = GetScanner("trivy")
	assert.True(t, ok)
	assert.Equal(t, "trivy", scanner.Name())
	assert.Equal(t, "trivy", scanner.ConverterName())

	scanner, ok = GetScanner("snyk")
	assert.True(t, ok)
	assert.Equal(t, "snyk", scanner.Name())
	assert.Equal(t, "snyk", scanner.ConverterName())
}

func TestScannerConverterNames(t *testing.T) {
	t.Parallel()

	// Verify each scanner's converter name matches its scanner name
	// This ensures the scanner output can be processed by the corresponding converter
	tests := []struct {
		scanner       Scanner
		converterName string
	}{
		{NewGrypeScanner(), "grype"},
		{NewTrivyScanner(), "trivy"},
		{NewSnykScanner(), "snyk"},
		{NewOSVScanner(), "osv"},
	}

	for _, tt := range tests {
		t.Run(tt.converterName, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.converterName, tt.scanner.Name())
			assert.Equal(t, tt.converterName, tt.scanner.ConverterName())
		})
	}
}

func TestGetAllScannerNames(t *testing.T) {
	t.Parallel()

	names := GetAllScannerNames()
	assert.Len(t, names, 4)
	assert.Contains(t, names, "grype")
	assert.Contains(t, names, "trivy")
	assert.Contains(t, names, "snyk")
	assert.Contains(t, names, "osv")
}

func TestParseScanWithOSV(t *testing.T) {
	t.Parallel()

	scanType, err := ParseScan("osv")
	assert.NoError(t, err)
	assert.Equal(t, OSV, scanType)
	assert.Equal(t, "osv", scanType.String())
}

func TestAllScannersDoesNotIncludeOSV(t *testing.T) {
	t.Parallel()

	// OSV is excluded from "all" because it doesn't support direct image scanning
	scanTypes, err := ParseScans("all")
	assert.NoError(t, err)

	for _, st := range scanTypes {
		assert.NotEqual(t, OSV, st, "OSV should not be in 'all' scanners")
	}
}

func TestGetAvailableScanners(t *testing.T) {
	t.Parallel()

	scanners := GetAvailableScanners()
	// Returns only installed scanners, so we can't assert on specific count
	assert.NotNil(t, scanners)
}

func TestGetAvailableScannerNames(t *testing.T) {
	t.Parallel()

	names := GetAvailableScannerNames()
	// Returns only installed scanners, so we can't assert on specific count
	assert.NotNil(t, names)
}

func TestGetSampleScanners(t *testing.T) {
	t.Parallel()

	samples := GetSampleScanners()
	assert.NotEmpty(t, samples, "should have sample scanner strings")
}

func TestRegistryAvailable(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	r.Register(NewGrypeScanner())
	r.Register(NewTrivyScanner())

	available := r.Available()
	// Available returns only installed scanners
	assert.NotNil(t, available)
}

func TestRegistryAvailableNames(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	r.Register(NewGrypeScanner())
	r.Register(NewTrivyScanner())

	names := r.AvailableNames()
	// Returns only installed scanners
	assert.NotNil(t, names)
}
