package snyk

import (
	"testing"

	"github.com/mchmarny/vimp/internal/parser"
	"github.com/stretchr/testify/assert"
)

func TestSnykConverter(t *testing.T) {
	c, err := parser.GetContainer("test.json")
	assert.NoError(t, err)
	list, err := Convert(c)
	assert.NoErrorf(t, err, "failed to convert: %v", err)
	assert.NotNil(t, list)
	assert.Greater(t, len(list), 0)

	noScoreCounter := 0
	for _, v := range list {
		assert.NotEmpty(t, v.ID)
		assert.NotEmpty(t, v.Package, v.ID)
		assert.NotEmpty(t, v.Severity, v.ID)
		assert.NotEmpty(t, v.Version, v.ID)
		assert.GreaterOrEqual(t, v.Score, float32(0), v.ID) // some matches won't have score
		if v.Score == 0 {
			noScoreCounter++
		}
	}
	assert.NotEqual(t, noScoreCounter, len(list))
}
