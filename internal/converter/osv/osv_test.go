package osv

import (
	"context"
	"testing"

	"github.com/mchmarny/vimp/internal/parser"
	"github.com/stretchr/testify/assert"
)

func TestOSVConverter(t *testing.T) {
	c, err := parser.GetContainer("test.json")
	assert.NoError(t, err)
	list, err := Convert(context.Background(), c)
	assert.NoErrorf(t, err, "failed to convert: %v", err)
	assert.NotNil(t, list)
	assert.Equal(t, 3, len(list))

	// Check that CVE IDs are preferred
	cveCount := 0
	for _, v := range list {
		assert.NotEmpty(t, v)
		assert.NotEmpty(t, v.Exposure)
		assert.NotEmpty(t, v.Package, v.Exposure)
		assert.NotEmpty(t, v.Version, v.Exposure)
		assert.Equal(t, "unknown", v.Severity, v.Exposure)
		// OSV doesn't provide CVSS scores
		assert.Equal(t, float32(0), v.Score, v.Exposure)

		if len(v.Exposure) > 4 && v.Exposure[:4] == "CVE-" {
			cveCount++
		}
	}
	// All 3 vulnerabilities in the test data have CVE aliases
	assert.Equal(t, 3, cveCount)
}

func TestOSVCanHandle(t *testing.T) {
	conv := New()
	assert.Equal(t, Name, conv.Name())

	// Should not handle nil
	assert.False(t, conv.CanHandle(nil))

	// Should handle valid OSV output
	c, err := parser.GetContainer("test.json")
	assert.NoError(t, err)
	assert.True(t, conv.CanHandle(c))
}

func TestOSVConvertNilContainer(t *testing.T) {
	conv := New()
	_, err := conv.Convert(context.Background(), nil)
	assert.Error(t, err)
}

func TestOSVHasFixedVersion(t *testing.T) {
	c, err := parser.GetContainer("test.json")
	assert.NoError(t, err)
	list, err := Convert(context.Background(), c)
	assert.NoError(t, err)

	// All vulnerabilities in test data have fixed versions
	for _, v := range list {
		assert.True(t, v.IsFixed, "expected %s to have fixed version", v.Exposure)
	}
}
