package processor

import (
	"testing"
)

func TestFormatString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		format Format
		want   string
	}{
		{FormatUnknown, "unknown"},
		{FormatGrypeJSON, "grype"},
		{FormatTrivyJSON, "trivy"},
		{FormatSnykJSON, "snyk"},
		{Format(99), "unknown"}, // unknown value
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			got := tc.format.String()
			if got != tc.want {
				t.Errorf("Format(%d).String() = %s, want %s", tc.format, got, tc.want)
			}
		})
	}
}

func TestParseFormatAll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		want    Format
		wantErr bool
	}{
		{"grype", FormatGrypeJSON, false},
		{"trivy", FormatTrivyJSON, false},
		{"snyk", FormatSnykJSON, false},
		{"unknown", FormatUnknown, true},
		{"", FormatUnknown, true},
		{"invalid", FormatUnknown, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := ParseFormat(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ParseFormat(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("ParseFormat(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestGetFormats(t *testing.T) {
	t.Parallel()

	formats := GetFormats()

	if len(formats) != 3 {
		t.Errorf("GetFormats() returned %d formats, want 3", len(formats))
	}

	// Check all expected formats are present
	expected := map[Format]bool{
		FormatGrypeJSON: false,
		FormatTrivyJSON: false,
		FormatSnykJSON:  false,
	}

	for _, f := range formats {
		if _, ok := expected[f]; ok {
			expected[f] = true
		}
	}

	for f, found := range expected {
		if !found {
			t.Errorf("GetFormats() missing format %v", f)
		}
	}
}

func TestGetFormatNames(t *testing.T) {
	t.Parallel()

	names := GetFormatNames()

	if len(names) == 0 {
		t.Error("GetFormatNames() returned empty slice")
	}

	// Should return converter names
	converterNames := GetConverterNames()
	if len(names) != len(converterNames) {
		t.Errorf("GetFormatNames() length %d != GetConverterNames() length %d", len(names), len(converterNames))
	}
}

func TestGetConverterNames(t *testing.T) {
	t.Parallel()

	names := GetConverterNames()

	if len(names) == 0 {
		t.Error("GetConverterNames() returned empty slice")
	}

	// Should have at least the core converters
	if len(names) < 3 {
		t.Errorf("GetConverterNames() returned %d names, want at least 3", len(names))
	}
}
