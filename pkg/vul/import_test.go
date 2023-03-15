package vul

import (
	"testing"

	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

func TestInvalidImport(t *testing.T) {
	err := Import(context.TODO(), nil)
	assert.Error(t, err)
	err = Import(context.TODO(), &types.ImportOptions{})
	assert.Error(t, err)
	err = Import(context.TODO(), &types.ImportOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
	})
	assert.Error(t, err)
	err = Import(context.TODO(), &types.ImportOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:   "bad/path/to/file.json",
	})
	assert.Error(t, err)
	err = Import(context.TODO(), &types.ImportOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:   "../../../examples/data/grype.json",
	})
	assert.Error(t, err)
}
