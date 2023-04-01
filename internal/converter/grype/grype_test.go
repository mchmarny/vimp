package grype

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrypeConverter(t *testing.T) {
	list, err := Convert("test.json")
	assert.NoErrorf(t, err, "failed to convert: %v", err)
	assert.NotNil(t, list)
	assert.Greater(t, len(list), 0)

	for _, v := range list {
		assert.NotEmpty(t, v)
		assert.NotEmpty(t, v.ID)
		assert.NotEmpty(t, v.Package, v.ID)
		assert.NotEmpty(t, v.Severity, v.ID)
		assert.NotEmpty(t, v.Version, v.ID)
		assert.GreaterOrEqual(t, v.Score, float32(0), v.ID) // some matches won't have score
	}
}
