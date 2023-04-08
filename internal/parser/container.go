package parser

import (
	"strings"

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

// GetFirstString returns the first non-empty string from the given keys.
func GetFirstString(v *gabs.Container, k ...string) string {
	if !v.Exists() {
		return ""
	}

	for _, key := range k {
		if !v.Exists(key) {
			continue
		}
		s := strings.ToLower(ToString(v.Search(key).Data()))
		if s != "" {
			return s
		}
	}

	return ""
}

func String(v *gabs.Container, k ...string) string {
	if !v.Exists() {
		return ""
	}

	for _, key := range k {
		if !v.Exists(key) {
			continue
		}
		s := ToString(v.Search(key).Data())
		if s != "" {
			return s
		}
	}

	return ""
}
