package source

import (
	"github.com/Jeffail/gabs/v2"
	"github.com/pkg/errors"
)

// NewSource returns a new Source from the given path.
func NewJSONSource(path string) (*Source, error) {
	if path == "" {
		return nil, errors.New("file is required")
	}

	c, err := gabs.ParseJSONFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse file: %s", path)
	}

	s := &Source{
		Data: c,
	}

	return s, nil
}

// Source represents a source of vulnerabilities.
type Source struct {
	// Data is the source data.
	Data *gabs.Container
}
