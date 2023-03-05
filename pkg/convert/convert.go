package convert

import (
	"context"

	"github.com/mchmarny/vulctl/pkg/convert/snyk"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
	aa "google.golang.org/api/containeranalysis/v1"
)

// VulnerabilityConverter is a function that converts a source to a list of AA notes.
type VulnerabilityConverter func(ctx context.Context, s *src.Source) ([]*aa.Note, error)

// GetConverter returns a vulnerability converter for the given format.
func GetConverter(format types.SourceFormat) (VulnerabilityConverter, error) {
	switch format {
	case types.SourceFormatSnykJSON:
		return snyk.Convert, nil
	default:
		return nil, errors.Errorf("unimplemented conversion format: %s", format)
	}
}
