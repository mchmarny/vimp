package vul

import (
	"testing"

	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestInvalidImport(t *testing.T) {
	err := Import(nil)
	assert.Error(t, err)
	err = Import(&types.InputOptions{})
	assert.Error(t, err)
	err = Import(&types.InputOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
	})
	assert.Error(t, err)
	err = Import(&types.InputOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:   "bad/path/to/file.json",
	})
	assert.Error(t, err)
	err = Import(&types.InputOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:   "../../../examples/data/grype.json",
	})
	assert.Error(t, err)
}
