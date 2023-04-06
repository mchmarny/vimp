package config

import (
	"net/url"

	"github.com/pkg/errors"
)

// EnsureURI ensures that the URI has a scheme.
func EnsureURI(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", errors.Wrap(err, "error parsing URI")
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	return u.String(), nil
}
