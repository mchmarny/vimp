package types

import "fmt"

const (
	SourceFormatUnknown   SourceFormat = iota
	SourceFormatGrypeJSON              // grype JSON format
	SourceFormatTrivyJSON              // trivy JSON format
	SourceFormatSnykJSON               // snyk JSON format
	SourceFormatOSVJSON                // osv-scanner JSON format

	SourceFormatUnknownName = "unknown"
	SourceFormatGrypeName   = "grype"
	SourceFormatTrivyName   = "trivy"
	SourceFormatSnykName    = "snyk"
	SourceFormatOSVName     = "osv"
)

// SourceFormat represents the source format.
type SourceFormat int64

// String returns the string representation of the source format.
func (f SourceFormat) String() string {
	switch f {
	case SourceFormatGrypeJSON:
		return SourceFormatGrypeName
	case SourceFormatTrivyJSON:
		return SourceFormatTrivyName
	case SourceFormatSnykJSON:
		return SourceFormatSnykName
	case SourceFormatOSVJSON:
		return SourceFormatOSVName
	default:
		return SourceFormatUnknownName
	}
}

// ParseSourceFormat parses the source format.
func ParseSourceFormat(s string) (SourceFormat, error) {
	switch s {
	case SourceFormatGrypeName:
		return SourceFormatGrypeJSON, nil
	case SourceFormatTrivyName:
		return SourceFormatTrivyJSON, nil
	case SourceFormatSnykName:
		return SourceFormatSnykJSON, nil
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
	}
}

// GetSourceFormatNames returns the names of the supported source formats.
func GetSourceFormatNames() []string {
	return []string{
		SourceFormatGrypeName,
		SourceFormatTrivyName,
		SourceFormatSnykName,
	}
}
