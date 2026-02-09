package processor

import (
	"testing"
)

func TestGetConverterNames(t *testing.T) {
	t.Parallel()

	names := GetConverterNames()

	if len(names) == 0 {
		t.Error("GetConverterNames() returned empty slice")
	}

	// Should have at least the core converters (grype, trivy, snyk, clair, osv, anchore)
	if len(names) < 6 {
		t.Errorf("GetConverterNames() returned %d names, want at least 6", len(names))
	}
}
