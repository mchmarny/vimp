package clair

import (
	"context"
	"testing"

	"github.com/mchmarny/vimp/internal/parser"
	"github.com/stretchr/testify/assert"
)

func TestClairConverter(t *testing.T) {
	c, err := parser.GetContainer("test.json")
	assert.NoError(t, err)
	list, err := Convert(context.Background(), c)
	assert.NoErrorf(t, err, "failed to convert: %v", err)
	assert.NotNil(t, list)
	assert.Greater(t, len(list), 0)

	for _, v := range list {
		assert.NotEmpty(t, v)
		assert.NotEmpty(t, v.Exposure)
		assert.NotEmpty(t, v.Package, v.Exposure)
		assert.NotEmpty(t, v.Severity, v.Exposure)
		assert.NotEmpty(t, v.Version, v.Exposure)
		// Clair doesn't provide CVSS scores
		assert.Equal(t, float32(0), v.Score, v.Exposure)
	}
}

func TestClairCanHandle(t *testing.T) {
	conv := New()
	assert.Equal(t, Name, conv.Name())

	// Should not handle nil
	assert.False(t, conv.CanHandle(nil))

	// Should handle valid Clair output
	c, err := parser.GetContainer("test.json")
	assert.NoError(t, err)
	assert.True(t, conv.CanHandle(c))
}

func TestClairConvertNilContainer(t *testing.T) {
	conv := New()
	_, err := conv.Convert(context.Background(), nil)
	assert.Error(t, err)
}
