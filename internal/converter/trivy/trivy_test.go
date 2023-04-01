package trivy

import (
	"testing"

	"github.com/mchmarny/vulctl/internal/source"
	"github.com/stretchr/testify/assert"
)

func TestTrivyConverter(t *testing.T) {
	s, err := source.NewJSONSource("test.json")
	assert.NoError(t, err)
	assert.NotNil(t, s)

	list, err := Convert(s)
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
