package converter

import (
	"context"

	"github.com/mchmarny/vulctl/pkg/converter/grype"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
	aa "google.golang.org/api/containeranalysis/v1"
)

// VulnerabilityConverter is a function that converts a source to a list of vulnerability occurrences.
type VulnerabilityConverter func(ctx context.Context, s *src.Source) ([]*aa.VulnerabilityOccurrence, error)

// GetConverter returns a vulnerability converter for the given format.
func GetConverter(format types.SourceFormat) (VulnerabilityConverter, error) {
	switch format {
	case types.SourceFormatGrypeJSON:
		return grype.Convert, nil
	default:
		return nil, errors.Errorf("unimplemented conversion format: %s", format)
	}
}
