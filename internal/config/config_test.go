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

	// Test that https scheme is removed
	got, err := RemoveSchema("https://docker.io/redis")
	assert.NoError(t, err)
	assert.NotEmpty(t, got)
	assert.NotContains(t, got, "https:")

	// Test empty string
	got, err = RemoveSchema("")
	assert.NoError(t, err)
	assert.Empty(t, got)

	// Test path without scheme
	got, err = RemoveSchema("docker.io/redis")
	assert.NoError(t, err)
	assert.NotEmpty(t, got)
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
