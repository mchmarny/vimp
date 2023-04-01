package parser

import (
	"github.com/Jeffail/gabs/v2"
	"github.com/pkg/errors"
)

// GetContainer returns a gabs container from the given path.
func GetContainer(path string) (*gabs.Container, error) {
	c, err := gabs.ParseJSONFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse file: %s", path)
	}
	return c, nil
}
