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
		assert.NotEmpty(t, v.CVE)
		assert.NotEmpty(t, v.Package, v.CVE)
		assert.NotEmpty(t, v.Severity, v.CVE)
		assert.NotEmpty(t, v.Version, v.CVE)
		assert.GreaterOrEqual(t, v.Score, float32(0), v.CVE) // some matches won't have score
		if v.Score == 0 {
			noScoreCounter++
		}
	}
	assert.NotEqual(t, noScoreCounter, len(list))
}
