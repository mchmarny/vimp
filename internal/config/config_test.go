package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoveSchema(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Basic cases
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "simple image without tag",
			input:    "nginx",
			expected: "nginx",
		},
		{
			name:     "simple image with tag",
			input:    "nginx:1.25",
			expected: "nginx:1.25",
		},
		{
			name:     "simple image with latest tag",
			input:    "redis:latest",
			expected: "redis:latest",
		},

		// Docker Hub references
		{
			name:     "docker hub official image",
			input:    "docker.io/library/nginx:1.25",
			expected: "docker.io/library/nginx:1.25",
		},
		{
			name:     "docker hub user image",
			input:    "docker.io/myuser/myimage:v1.0",
			expected: "docker.io/myuser/myimage:v1.0",
		},
		{
			name:     "docker hub without tag",
			input:    "docker.io/redis",
			expected: "docker.io/redis",
		},

		// Other registries
		{
			name:     "ghcr.io registry",
			input:    "ghcr.io/owner/repo:v1.0",
			expected: "ghcr.io/owner/repo:v1.0",
		},
		{
			name:     "gcr.io registry",
			input:    "gcr.io/project-id/image:tag",
			expected: "gcr.io/project-id/image:tag",
		},
		{
			name:     "quay.io registry",
			input:    "quay.io/organization/image:latest",
			expected: "quay.io/organization/image:latest",
		},
		{
			name:     "ecr registry",
			input:    "123456789.dkr.ecr.us-east-1.amazonaws.com/repo:tag",
			expected: "123456789.dkr.ecr.us-east-1.amazonaws.com/repo:tag",
		},

		// Registry with port (important corner case)
		{
			name:     "localhost with port",
			input:    "localhost:5000/myimage:v1",
			expected: "localhost:5000/myimage:v1",
		},
		{
			name:     "private registry with port",
			input:    "registry.example.com:5000/app:latest",
			expected: "registry.example.com:5000/app:latest",
		},
		{
			name:     "ip address with port",
			input:    "192.168.1.100:5000/image:tag",
			expected: "192.168.1.100:5000/image:tag",
		},

		// Digest references
		{
			name:     "image with digest only",
			input:    "nginx@sha256:abc123def456",
			expected: "nginx@sha256:abc123def456",
		},
		{
			name:     "image with tag and digest",
			input:    "nginx:1.25@sha256:abc123def456",
			expected: "nginx:1.25@sha256:abc123def456",
		},
		{
			name:     "full reference with digest",
			input:    "docker.io/library/nginx@sha256:e688fed0b0c7513a63364959e7d389c37ac8ecac7a6c6a31455eca2f5a71ab8b",
			expected: "docker.io/library/nginx@sha256:e688fed0b0c7513a63364959e7d389c37ac8ecac7a6c6a31455eca2f5a71ab8b",
		},
		{
			name:     "registry with port and digest",
			input:    "localhost:5000/image@sha256:abc123",
			expected: "localhost:5000/image@sha256:abc123",
		},

		// URL schemes that should be removed
		{
			name:     "https scheme removed",
			input:    "https://docker.io/redis",
			expected: "docker.io/redis",
		},
		{
			name:     "https with tag",
			input:    "https://ghcr.io/owner/repo:v1.0",
			expected: "ghcr.io/owner/repo:v1.0",
		},
		{
			name:     "http scheme removed",
			input:    "http://localhost:5000/image:tag",
			expected: "localhost:5000/image:tag",
		},

		// Deeply nested paths
		{
			name:     "deeply nested path",
			input:    "gcr.io/project/team/app/component:v1.2.3",
			expected: "gcr.io/project/team/app/component:v1.2.3",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := RemoveSchema(tc.input)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestGetDefaultDBPath(t *testing.T) {
	t.Parallel()

	path := GetDefaultDBPath()

	// Should start with sqlite:// prefix
	assert.True(t, strings.HasPrefix(path, LocalStorePrefix), "should start with sqlite://")

	// Should end with the default filename
	assert.True(t, strings.HasSuffix(path, FileNameDefault), "should end with .vimp.db")

	// Should contain home directory path (unless HOME is not set)
	home, err := os.UserHomeDir()
	if err == nil {
		assert.Contains(t, path, home)
	}
}

func TestGetTempFilePath(t *testing.T) {
	t.Parallel()

	prefix := "test-scan"
	path := GetTempFilePath(prefix)

	// Should start with temp directory
	tempDir := os.TempDir()
	assert.True(t, strings.HasPrefix(path, tempDir), "should be in temp directory")

	// Should contain prefix
	assert.Contains(t, filepath.Base(path), prefix)

	// Should end with .json
	assert.True(t, strings.HasSuffix(path, ".json"), "should end with .json")
}

func TestGetTempFilePathMultipleCalls(t *testing.T) {
	t.Parallel()

	// Verify the function returns valid paths
	path1 := GetTempFilePath("test1")
	path2 := GetTempFilePath("test2")

	// Both should be valid temp paths
	assert.True(t, strings.HasPrefix(path1, os.TempDir()))
	assert.True(t, strings.HasPrefix(path2, os.TempDir()))

	// Different prefixes should yield different paths
	assert.NotEqual(t, path1, path2)
}
