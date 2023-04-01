package converter

import (
	"github.com/mchmarny/vulctl/internal/converter/grype"
	"github.com/mchmarny/vulctl/internal/converter/snyk"
	"github.com/mchmarny/vulctl/internal/converter/trivy"
	"github.com/mchmarny/vulctl/internal/source"
	"github.com/mchmarny/vulctl/pkg/vulnerability"
	"github.com/pkg/errors"
)

// VulnerabilityMapper is a function that converts a source to a list of common vulnerability types.
type VulnerabilityMapper func(s *source.Source) ([]*vulnerability.Item, error)

// GetMapper returns a vulnerability converter for the given source format.
func GetMapper(format source.Format) (VulnerabilityMapper, error) {
	switch format {
	case source.FormatSnykJSON:
		return snyk.Convert, nil
	case source.FormatTrivyJSON:
		return trivy.Convert, nil
	case source.FormatGrypeJSON:
		return grype.Convert, nil
	default:
		return nil, errors.Errorf("unimplemented conversion format: %s", format)
	}
}
