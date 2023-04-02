package processor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidProcess(t *testing.T) {
	err := Process(nil)
	assert.Error(t, err)
	err = Process(&Options{})
	assert.Error(t, err)
	err = Process(&Options{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
	})
	assert.Error(t, err)
	err = Process(&Options{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:   "bad/path/to/file.json",
	})
	assert.Error(t, err)
	err = Process(&Options{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:   "../../../examples/data/grype.json",
	})
	assert.Error(t, err)
}
