package snyk

import (
	"testing"

	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestSnykConverter(t *testing.T) {
	opt := &types.InputOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:   "../../../examples/data/snyk.json",
		Format: types.SourceFormatSnykJSON,
	}
	s, err := src.NewSource(opt)
	assert.NoError(t, err)
	assert.NotNil(t, s)

	list, err := Convert(s)
	assert.NoErrorf(t, err, "failed to convert: %v", err)
	assert.NotNil(t, list)

	for id, v := range list {
		assert.NotEmpty(t, id)
		assert.NotEmpty(t, v)
		assert.NotEmpty(t, v.ID)
		assert.NotEmpty(t, v.Package)
		assert.NotEmpty(t, v.Severity)
		assert.NotEmpty(t, v.Version)
		assert.GreaterOrEqual(t, v.Score, float32(0), id) // some matches won't have score
	}
}
