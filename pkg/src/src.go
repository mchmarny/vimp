package src

import (
	"github.com/Jeffail/gabs/v2"
	"github.com/pkg/errors"
)

// NewSource returns a new Source from the given path.
func NewSource(path string) (*Source, error) {
	if path == "" {
		return nil, errors.New("file is required")
	}

	c, err := gabs.ParseJSONFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse file: %s", path)
	}

	s := &Source{
		Path: path,
		Data: c,
	}

	return s, nil
}

type Source struct {
	// Path is the path to the source file.
	Path string

	Data *gabs.Container
}
