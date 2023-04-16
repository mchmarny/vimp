package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
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
	v = strings.TrimPrefix(v, "https://")

	if strings.Contains(v, "@") {
		return v, nil
	}

	if !strings.Contains(v, ".") {
		v = fmt.Sprintf("docker.io/%s", v)
	}

	ref, err := name.ParseReference(v)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse image URL from: %s", v)
	}

	fmt.Printf("ref: %v\n", ref)

	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", errors.Wrapf(err, "failed to fetch image from: %s", ref.String())
	}

	dig, err := img.Digest()
	if err != nil {
		return "", errors.Wrapf(err, "failed to get digest for image: %s", ref.String())
	}

	fmt.Printf("dig: %v\n", dig)

	return fmt.Sprintf("%s@%s", v, dig.String()), nil
}
