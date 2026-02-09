package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
)

// RemoveTag removes the tag from an image reference, preserving registry ports.
// Examples:
//   - docker.io/library/nginx:1.25 -> docker.io/library/nginx
//   - localhost:5000/image:tag -> localhost:5000/image
//   - nginx:latest -> nginx
//   - nginx -> nginx
func RemoveTag(uri string) string {
	// If there's no colon, there's no tag (or port)
	if !strings.Contains(uri, ":") {
		return uri
	}

	// Find the last "/" to identify where the image name starts
	lastSlash := strings.LastIndex(uri, "/")

	// If there's a "/" the tag (if any) is after the last ":" that comes after the last "/"
	if lastSlash != -1 {
		afterSlash := uri[lastSlash+1:]
		if colonIdx := strings.LastIndex(afterSlash, ":"); colonIdx != -1 {
			// There's a tag after the last slash
			return uri[:lastSlash+1+colonIdx]
		}
		// No tag after the last slash
		return uri
	}

	// No slash - simple image name like "nginx:1.25"
	if colonIdx := strings.LastIndex(uri, ":"); colonIdx != -1 {
		return uri[:colonIdx]
	}

	return uri
}

// RemoveSchema cleans up a URI by removing the scheme (e.g., https://).
// Container image references like "nginx:1.25" are returned unchanged since
// the colon is a tag separator, not a scheme delimiter.
func RemoveSchema(uri string) (string, error) {
	// Only treat as URL if it has a proper scheme with ://
	// This prevents "nginx:1.25" from being parsed as scheme="nginx" opaque="1.25"
	if !strings.Contains(uri, "://") {
		return uri, nil
	}

	u, err := url.Parse(uri)
	if err != nil {
		return "", errors.Wrap(err, "error parsing URI")
	}
	if u.Scheme != "" {
		u.Scheme = ""
	}
	// Remove leading slashes from the result (e.g., "//docker.io/nginx" -> "docker.io/nginx")
	return strings.TrimPrefix(u.String(), "//"), nil
}

// NormalizeImageName adds docker.io/library/ prefix to simple image names.
// Examples:
//   - nginx -> docker.io/library/nginx
//   - nginx:1.25 -> docker.io/library/nginx:1.25
//   - myuser/myimage -> docker.io/myuser/myimage
//   - docker.io/library/nginx -> docker.io/library/nginx (unchanged)
//   - localhost:5000/myimage -> localhost:5000/myimage (unchanged, registry with port)
func NormalizeImageName(v string) string {
	// Check if this is a simple image name (like "nginx" or "nginx:1.25")
	// that needs docker.io/ prefix. We check for "/" to detect if a registry
	// path is already present. Simple names like "nginx:1.25" don't have "/".
	if !strings.Contains(v, "/") {
		return fmt.Sprintf("docker.io/library/%s", v)
	}

	// Has "/" - check the first part to determine if it's a registry or Docker Hub user
	firstPart := strings.Split(v, "/")[0]

	// If first part contains "." (like docker.io, gcr.io) or ":" (like localhost:5000),
	// it's a registry hostname. Otherwise it's a Docker Hub user image.
	if strings.Contains(firstPart, ".") || strings.Contains(firstPart, ":") {
		return v
	}

	// It's a Docker Hub user image like "myuser/myimage"
	return fmt.Sprintf("docker.io/%s", v)
}

// GetDigest returns the digest of the image.
// Could result in uri that has both a tag and a digest.
func GetDigest(v string) (string, error) {
	v = strings.TrimPrefix(v, "https://")

	if strings.Contains(v, "@") {
		return v, nil
	}

	v = NormalizeImageName(v)

	ref, err := name.ParseReference(v)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse image URL from: %s", v)
	}

	slog.Debug("parsed reference", "ref", ref)

	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", errors.Wrapf(err, "failed to fetch image from: %s", ref.String())
	}

	dig, err := img.Digest()
	if err != nil {
		return "", errors.Wrapf(err, "failed to get digest for image: %s", ref.String())
	}

	slog.Debug("resolved digest", "digest", dig)

	return fmt.Sprintf("%s@%s", v, dig.String()), nil
}
