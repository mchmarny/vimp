package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/pkg/errors"
)

const (
	expectedParts = 2
)

// RemoveSchema cleans up a URI by removing the scheme.
func RemoveTag(uri string) string {
	if !strings.Contains(uri, ":") {
		return uri
	}
	return strings.Split(uri, ":")[0]
}

// RemoveSchema cleans up a URI by removing the scheme.
func RemoveSchema(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", errors.Wrap(err, "error parsing URI")
	}
	if u.Scheme != "" {
		u.Scheme = ""
	}
	return u.String(), nil
}

// GetDigest returns the digest of the image.
// Could result in uri that has both a tag and a digest.
func GetDigest(v string) (string, error) {
	// if the image uri already contains a digest, return it
	parts := strings.Split(v, "@")
	if len(parts) == expectedParts {
		return v, nil
	}

	uri := v
	if strings.HasPrefix(v, "https://") {
		uri = strings.TrimPrefix(v, "https://")
	}

	// this should work for tags as well as basic uris which
	// will resolve to the latest tag
	digest, err := crane.Digest(uri)
	if err != nil {
		return "", errors.Wrapf(err, "getting digest from %s", v)
	}

	return fmt.Sprintf("%s@%s", v, digest), nil
}
