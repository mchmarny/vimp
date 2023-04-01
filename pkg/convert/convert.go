package convert

import (
	"github.com/mchmarny/vulctl/pkg/convert/grype"
	"github.com/mchmarny/vulctl/pkg/convert/snyk"
	"github.com/mchmarny/vulctl/pkg/convert/trivy"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
)

// VulnerabilityConverter is a function that converts a source to a list of common vulnerability types.
type VulnerabilityConverter func(s *src.Source) (map[string]*types.Vulnerability, error)

// GetConverter returns a vulnerability converter for the given format.
func GetConverter(format types.SourceFormat) (VulnerabilityConverter, error) {
	switch format {
	case types.SourceFormatSnykJSON:
		return snyk.Convert, nil
	case types.SourceFormatTrivyJSON:
		return trivy.Convert, nil
	case types.SourceFormatGrypeJSON:
		return grype.Convert, nil
	default:
		return nil, errors.Errorf("unimplemented conversion format: %s", format)
	}
}
