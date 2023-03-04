package types

import "fmt"

const (
	SourceFormatUnknown   SourceFormat = iota
	SourceFormatGrypeJSON              // grype JSON format
	SourceFormatTrivyJSON              // trivy JSON format
	SourceFormatSnykJSON               // snyk JSON format
	SourceFormatOVS                    // OVS format

	SourceFormatUnknownName   = "unknown"
	SourceFormatGrypeJSONName = "grype"
	SourceFormatTrivyJSONName = "trivy"
	SourceFormatSnykJSONName  = "snyk"
	SourceFormatOVSName       = "ovs"
)

// SourceFormat represents the source format.
type SourceFormat int64

// String returns the string representation of the source format.
func (f SourceFormat) String() string {
	switch f {
	case SourceFormatGrypeJSON:
		return SourceFormatGrypeJSONName
	case SourceFormatTrivyJSON:
		return SourceFormatTrivyJSONName
	case SourceFormatSnykJSON:
		return SourceFormatSnykJSONName
	case SourceFormatOVS:
		return SourceFormatOVSName
	default:
		return SourceFormatUnknownName
	}
}

// ParseSourceFormat parses the source format.
func ParseSourceFormat(s string) (SourceFormat, error) {
	switch s {
	case SourceFormatGrypeJSONName:
		return SourceFormatGrypeJSON, nil
	case SourceFormatTrivyJSONName:
		return SourceFormatTrivyJSON, nil
	case SourceFormatSnykJSONName:
		return SourceFormatSnykJSON, nil
	case SourceFormatOVSName:
		return SourceFormatOVS, nil
	default:
		return SourceFormatUnknown, fmt.Errorf("unknown format: %s", s)
	}
}

// GetSourceFormats returns the supported source formats.
func GetSourceFormats() []SourceFormat {
	return []SourceFormat{
		SourceFormatGrypeJSON,
		SourceFormatTrivyJSON,
		SourceFormatSnykJSON,
		SourceFormatOVS,
	}
}

// GetSourceFormatNames returns the names of the supported source formats.
func GetSourceFormatNames() []string {
	var names []string
	for _, f := range GetSourceFormats() {
		names = append(names, f.String())
	}
	return names
}
