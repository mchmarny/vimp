package config

import (
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

func TestRemoveTag(t *testing.T) {
	t.Parallel()
	u := RemoveTag("docker.io/redis:latest")
	assert.Equal(t, "docker.io/redis", u)

	u = RemoveTag("docker.io/redis")
	assert.Equal(t, "docker.io/redis", u)
}
