package trivy

import (
	"testing"

	"github.com/mchmarny/vimp/internal/parser"
	"github.com/stretchr/testify/assert"
)

func TestTrivyConverter(t *testing.T) {
	c, err := parser.GetContainer("test.json")
	assert.NoError(t, err)
	list, err := Convert(c)
	assert.NoErrorf(t, err, "failed to convert: %v", err)
	assert.NotNil(t, list)
	assert.Greater(t, len(list), 0)

	for _, v := range list {
		assert.NotEmpty(t, v)
		assert.NotEmpty(t, v.Exposure)
		assert.NotEmpty(t, v.Package, v.Exposure)
		assert.NotEmpty(t, v.Severity, v.Exposure)
		assert.NotEmpty(t, v.Version, v.Exposure)
		assert.GreaterOrEqual(t, v.Score, float32(0), v.Exposure) // some matches won't have score
	}
}
