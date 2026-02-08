package anchore

import (
	"context"
	"testing"

	"github.com/mchmarny/vimp/internal/parser"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/stretchr/testify/assert"
)

func TestAnchoreConverter(t *testing.T) {
	c, err := parser.GetContainer("test.json")
	assert.NoError(t, err)
	list, err := Convert(context.Background(), c)
	assert.NoErrorf(t, err, "failed to convert: %v", err)
	assert.NotNil(t, list)
	assert.Equal(t, 3, len(list))

	for _, v := range list {
		assert.NotEmpty(t, v)
		assert.NotEmpty(t, v.Exposure)
		assert.NotEmpty(t, v.Package, v.Exposure)
		assert.NotEmpty(t, v.Severity, v.Exposure)
		assert.NotEmpty(t, v.Version, v.Exposure)
		// Anchore provides CVSS scores via nvd_data
		assert.GreaterOrEqual(t, v.Score, float32(0), v.Exposure)
	}

	// Check specific values
	cveMap := make(map[string]*data.Vulnerability)
	for _, v := range list {
		cveMap[v.Exposure] = v
	}

	// CVE-2021-3711 should have fix
	assert.True(t, cveMap["CVE-2021-3711"].IsFixed)
	// CVE-2021-22945 has fix = "None"
	assert.False(t, cveMap["CVE-2021-22945"].IsFixed)
	// CVE-2022-1292 should have fix
	assert.True(t, cveMap["CVE-2022-1292"].IsFixed)

	// Check CVSS scores - should prefer v3
	assert.Equal(t, float32(9.8), cveMap["CVE-2021-3711"].Score)
	assert.Equal(t, float32(7.5), cveMap["CVE-2021-22945"].Score)
}

func TestAnchoreCanHandle(t *testing.T) {
	conv := New()
	assert.Equal(t, Name, conv.Name())

	// Should not handle nil
	assert.False(t, conv.CanHandle(nil))

	// Should handle valid Anchore output
	c, err := parser.GetContainer("test.json")
	assert.NoError(t, err)
	assert.True(t, conv.CanHandle(c))
}

func TestAnchoreConvertNilContainer(t *testing.T) {
	conv := New()
	_, err := conv.Convert(context.Background(), nil)
	assert.Error(t, err)
}
