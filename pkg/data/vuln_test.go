package data

import (
	"testing"
)

func TestVulnerabilityString(t *testing.T) {
	t.Parallel()

	v := &Vulnerability{
		Exposure: "CVE-2021-44228",
		Package:  "log4j-core",
		Version:  "2.14.1",
		Severity: "critical",
		Score:    10.0,
		IsFixed:  false,
	}

	got := v.String()
	if got == "" {
		t.Error("String() returned empty string")
	}

	// Should contain all fields
	if !contains(got, "CVE-2021-44228") {
		t.Errorf("String() missing exposure, got %s", got)
	}
	if !contains(got, "log4j-core") {
		t.Errorf("String() missing package, got %s", got)
	}
}

func TestVulnerabilityGetID(t *testing.T) {
	t.Parallel()

	v1 := &Vulnerability{
		Exposure: "CVE-2021-44228",
		Package:  "log4j-core",
		Version:  "2.14.1",
	}
	v2 := &Vulnerability{
		Exposure: "CVE-2021-44228",
		Package:  "log4j-core",
		Version:  "2.14.1",
	}
	v3 := &Vulnerability{
		Exposure: "CVE-2021-44228",
		Package:  "log4j-core",
		Version:  "2.15.0", // different version
	}

	// Same content should produce same ID
	id1 := v1.GetID()
	id2 := v2.GetID()
	if id1 != id2 {
		t.Errorf("GetID() should be deterministic: %s != %s", id1, id2)
	}

	// Different content should produce different ID
	id3 := v3.GetID()
	if id1 == id3 {
		t.Errorf("GetID() should differ for different versions: %s == %s", id1, id3)
	}

	// ID should be hex string of expected length (SHA256 = 64 chars)
	if len(id1) != 64 {
		t.Errorf("GetID() should return 64-char hex string, got %d chars", len(id1))
	}
}

func TestVulnerabilityGetIDEmpty(t *testing.T) {
	t.Parallel()

	v := &Vulnerability{}
	id := v.GetID()

	// Even empty vulnerability should produce valid ID
	if len(id) != 64 {
		t.Errorf("GetID() should work for empty vuln, got %d chars", len(id))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
