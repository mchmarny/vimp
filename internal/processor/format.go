package processor

import (
	"fmt"
)

const (
	FormatUnknown   Format = iota
	FormatGrypeJSON        // grype JSON format
	FormatTrivyJSON        // trivy JSON format
	FormatSnykJSON         // snyk JSON format

	FormatUnknownName   = "unknown"
	FormatGrypeJSONName = "grype"
	FormatTrivyJSONName = "trivy"
	FormatSnykJSONName  = "snyk"
)

// Format represents the source format.
//
// Deprecated: Use converter.Registry.Detect() instead.
type Format int64

// String returns the string representation of the source format.
func (f Format) String() string {
	switch f {
	case FormatUnknown:
		return FormatUnknownName
	case FormatGrypeJSON:
		return FormatGrypeJSONName
	case FormatTrivyJSON:
		return FormatTrivyJSONName
	case FormatSnykJSON:
		return FormatSnykJSONName
	}
	return FormatUnknownName
}

// ParseFormat parses the source format.
func ParseFormat(s string) (Format, error) {
	switch s {
	case FormatGrypeJSONName:
		return FormatGrypeJSON, nil
	case FormatTrivyJSONName:
		return FormatTrivyJSON, nil
	case FormatSnykJSONName:
		return FormatSnykJSON, nil
	default:
		return FormatUnknown, fmt.Errorf("unknown format: %s", s)
	}
}

// GetFormats returns the supported source formats.
//
// Deprecated: Use GetConverterNames() instead.
func GetFormats() []Format {
	return []Format{
		FormatGrypeJSON,
		FormatTrivyJSON,
		FormatSnykJSON,
	}
}

// GetFormatNames returns the names of the supported source formats.
//
// Deprecated: Use GetConverterNames() instead.
func GetFormatNames() []string {
	return GetConverterNames()
}
