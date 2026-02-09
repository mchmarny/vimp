package registry

import (
	"context"
	"log/slog"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	"golang.org/x/mod/semver"
)

// DiscoverTags returns the N most recent tags for an image.
// Tags are sorted by semantic versioning (descending).
// Assumes user is authenticated via default keychain.
func DiscoverTags(ctx context.Context, imageRef string, count int) ([]string, error) {
	if count < 1 {
		return nil, errors.New("count must be at least 1")
	}

	slog.Debug("parsing image reference", "ref", imageRef)

	// Parse reference to get repository
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse image reference: %s", imageRef)
	}

	repo := ref.Context()
	slog.Debug("resolved repository", "repo", repo.String())

	// List all tags
	slog.Debug("listing tags from registry")
	tags, err := remote.List(repo, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list tags for: %s", repo.String())
	}

	if len(tags) == 0 {
		return nil, errors.Errorf("no tags found for: %s", repo.String())
	}

	slog.Debug("found tags", "count", len(tags))

	// Sort by semver (fast, no network calls)
	sorted := sortTagsBySemver(tags)
	slog.Debug("sorted tags by semver")

	// Return top N
	if count > len(sorted) {
		count = len(sorted)
	}

	result := sorted[:count]
	slog.Debug("selected top tags", "count", len(result), "tags", result)

	return result, nil
}

// sortTagsBySemver sorts tags using semantic versioning (descending).
// Non-semver tags are placed after semver tags, sorted alphabetically.
func sortTagsBySemver(tags []string) []string {
	result := make([]string, len(tags))
	copy(result, tags)

	sort.Slice(result, func(i, j int) bool {
		vi := normalizeVersion(result[i])
		vj := normalizeVersion(result[j])

		// Both valid semver: compare semantically
		if semver.IsValid(vi) && semver.IsValid(vj) {
			return semver.Compare(vi, vj) > 0 // descending
		}

		// Only one is valid semver: prefer semver
		if semver.IsValid(vi) {
			return true
		}
		if semver.IsValid(vj) {
			return false
		}

		// Neither is semver: alphabetical descending
		return result[i] > result[j]
	})

	return result
}

// normalizeVersion adds 'v' prefix if needed for semver comparison.
func normalizeVersion(tag string) string {
	if strings.HasPrefix(tag, "v") {
		return tag
	}
	return "v" + tag
}

// BuildImageURIs creates full image URIs from a base reference and list of tags.
func BuildImageURIs(baseRef string, tags []string) ([]string, error) {
	slog.Debug("building image URIs", "base", baseRef, "tagCount", len(tags))

	ref, err := name.ParseReference(baseRef)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse base reference: %s", baseRef)
	}

	repo := ref.Context()
	uris := make([]string, len(tags))

	for i, tag := range tags {
		uris[i] = repo.String() + ":" + tag
	}

	slog.Debug("built image URIs", "uris", uris)

	return uris, nil
}
