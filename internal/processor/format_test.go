package processor

import (
	"testing"

	"github.com/mchmarny/vulctl/internal/parser"
	"github.com/stretchr/testify/assert"
)

func TestGrypeFormat(t *testing.T) {
	c, err := parser.GetContainer("../converter/grype/test.json")
	assert.NoError(t, err)
	assert.Equal(t, FormatGrypeJSON, discoverFormat(c))
}

func TestSnykFormat(t *testing.T) {
	c, err := parser.GetContainer("../converter/snyk/test.json")
	assert.NoError(t, err)
	assert.Equal(t, FormatSnykJSON, discoverFormat(c))
}

func TestTrivyFormat(t *testing.T) {
	c, err := parser.GetContainer("../converter/trivy/test.json")
	assert.NoError(t, err)
	assert.Equal(t, FormatTrivyJSON, discoverFormat(c))
}
