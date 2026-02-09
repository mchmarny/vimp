package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDigestFromBasicDocker(t *testing.T) {
	t.Parallel()
	u, err := GetDigest("https://docker.io/redis")
	assert.NoError(t, err)
	assert.NotEmpty(t, u)
}

func TestGetDigestWithTag(t *testing.T) {
	t.Parallel()
	u, err := GetDigest("docker.io/redis:latest")
	assert.NoError(t, err)
	assert.NotEmpty(t, u)
}

func TestGetDigestWithDigest(t *testing.T) {
	t.Parallel()
	u, err := GetDigest("docker.io/redis@sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448")
	assert.NoError(t, err)
	assert.NotEmpty(t, u)
}

// TestGetDigestSimpleImageWithTag verifies that simple image names like "nginx:1.25"
// get the docker.io/library/ prefix added correctly.
func TestGetDigestSimpleImageWithTag(t *testing.T) {
	t.Parallel()
	u, err := GetDigest("nginx:1.25")
	assert.NoError(t, err)
	assert.NotEmpty(t, u)
	// Should have docker.io/library/ prefix
	assert.True(t, strings.HasPrefix(u, "docker.io/library/nginx:1.25@sha256:"),
		"expected docker.io/library/nginx:1.25@sha256:..., got %s", u)
}

// TestGetDigestSimpleImageNoTag verifies simple image names without tags.
func TestGetDigestSimpleImageNoTag(t *testing.T) {
	t.Parallel()
	u, err := GetDigest("redis")
	assert.NoError(t, err)
	assert.NotEmpty(t, u)
	// Should have docker.io/library/ prefix
	assert.True(t, strings.HasPrefix(u, "docker.io/library/redis"),
		"expected docker.io/library/redis..., got %s", u)
}

// TestGetDigestUserImage verifies Docker Hub user images get docker.io/ prefix.
func TestGetDigestUserImage(t *testing.T) {
	t.Parallel()
	// Using a known public image
	u, err := GetDigest("library/redis:latest")
	assert.NoError(t, err)
	assert.NotEmpty(t, u)
	// Should have docker.io/ prefix (not docker.io/library/)
	assert.True(t, strings.HasPrefix(u, "docker.io/library/redis"),
		"expected docker.io/library/redis..., got %s", u)
}

// TestGetDigestFullyQualified verifies fully qualified images are unchanged.
func TestGetDigestFullyQualified(t *testing.T) {
	t.Parallel()
	u, err := GetDigest("docker.io/library/nginx:1.25")
	assert.NoError(t, err)
	assert.NotEmpty(t, u)
	assert.True(t, strings.HasPrefix(u, "docker.io/library/nginx:1.25@sha256:"),
		"expected docker.io/library/nginx:1.25@sha256:..., got %s", u)
}

func TestNormalizeImageName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Simple image names get docker.io/library/ prefix
		{
			name:     "simple image without tag",
			input:    "nginx",
			expected: "docker.io/library/nginx",
		},
		{
			name:     "simple image with tag",
			input:    "nginx:1.25",
			expected: "docker.io/library/nginx:1.25",
		},
		{
			name:     "simple image with latest",
			input:    "redis:latest",
			expected: "docker.io/library/redis:latest",
		},

		// Docker Hub user images get docker.io/ prefix
		{
			name:     "user image",
			input:    "myuser/myimage",
			expected: "docker.io/myuser/myimage",
		},
		{
			name:     "user image with tag",
			input:    "myuser/myimage:v1.0",
			expected: "docker.io/myuser/myimage:v1.0",
		},
		{
			name:     "library user image",
			input:    "library/nginx",
			expected: "docker.io/library/nginx",
		},

		// Fully qualified images are unchanged
		{
			name:     "docker.io already present",
			input:    "docker.io/library/nginx:1.25",
			expected: "docker.io/library/nginx:1.25",
		},
		{
			name:     "ghcr.io image",
			input:    "ghcr.io/owner/repo:v1.0",
			expected: "ghcr.io/owner/repo:v1.0",
		},
		{
			name:     "gcr.io image",
			input:    "gcr.io/project/image:tag",
			expected: "gcr.io/project/image:tag",
		},
		{
			name:     "localhost with port",
			input:    "localhost:5000/myimage:v1",
			expected: "localhost:5000/myimage:v1",
		},
		{
			name:     "private registry",
			input:    "registry.example.com/app:latest",
			expected: "registry.example.com/app:latest",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeImageName(tc.input)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestRemoveTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Basic cases
		{
			name:     "image without tag",
			input:    "nginx",
			expected: "nginx",
		},
		{
			name:     "simple image with tag",
			input:    "nginx:1.25",
			expected: "nginx",
		},
		{
			name:     "image with latest tag",
			input:    "redis:latest",
			expected: "redis",
		},

		// Docker Hub references
		{
			name:     "docker hub with tag",
			input:    "docker.io/redis:latest",
			expected: "docker.io/redis",
		},
		{
			name:     "docker hub without tag",
			input:    "docker.io/redis",
			expected: "docker.io/redis",
		},
		{
			name:     "docker hub library with version tag",
			input:    "docker.io/library/nginx:1.25",
			expected: "docker.io/library/nginx",
		},

		// Registry with port (important corner case)
		{
			name:     "localhost with port and tag",
			input:    "localhost:5000/myimage:v1",
			expected: "localhost:5000/myimage",
		},
		{
			name:     "localhost with port no tag",
			input:    "localhost:5000/myimage",
			expected: "localhost:5000/myimage",
		},
		{
			name:     "private registry with port and tag",
			input:    "registry.example.com:5000/app:latest",
			expected: "registry.example.com:5000/app",
		},

		// Other registries
		{
			name:     "ghcr.io with tag",
			input:    "ghcr.io/owner/repo:v1.0.0",
			expected: "ghcr.io/owner/repo",
		},
		{
			name:     "gcr.io with tag",
			input:    "gcr.io/project/image:tag",
			expected: "gcr.io/project/image",
		},

		// Nested paths
		{
			name:     "deeply nested with tag",
			input:    "gcr.io/project/team/app:v1.2.3",
			expected: "gcr.io/project/team/app",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := RemoveTag(tc.input)
			assert.Equal(t, tc.expected, got)
		})
	}
}
