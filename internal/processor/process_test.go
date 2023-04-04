package processor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidProcess(t *testing.T) {
	err := Import(nil)
	assert.Error(t, err)
	err = Import(&ImportOptions{})
	assert.Error(t, err)
	err = Import(&ImportOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
	})
	assert.Error(t, err)
	err = Import(&ImportOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:   "bad/path/to/file.json",
	})
	assert.Error(t, err)
	err = Import(&ImportOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:   "../../../examples/data/grype.json",
	})
	assert.Error(t, err)
}
