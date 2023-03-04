package src

import (
	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
)

// NewSource returns a new Source from the given path.
func NewSource(opt *types.ImportOptions) (*Source, error) {
	if opt == nil {
		return nil, errors.New("options required")
	}

	if opt.File == "" {
		return nil, errors.New("file is required")
	}

	c, err := gabs.ParseJSONFile(opt.File)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse file: %s", opt.File)
	}

	s := &Source{
		ImageURI: opt.ImageURI,
		Data:     c,
	}

	return s, nil
}

type Source struct {
	// ImageURI is the image URI.
	ImageURI string

	// Data is the source data.
	Data *gabs.Container
}
