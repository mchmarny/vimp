package processor

import (
	"testing"

	"github.com/mchmarny/vimp/internal/converter/grype"
	"github.com/mchmarny/vimp/internal/converter/snyk"
	"github.com/mchmarny/vimp/internal/converter/trivy"
	"github.com/mchmarny/vimp/internal/parser"
	"github.com/stretchr/testify/assert"
)

func TestGrypeFormat(t *testing.T) {
	t.Parallel()
	c, err := parser.GetContainer("../converter/grype/test.json")
	assert.NoError(t, err)

	conv, err := defaultRegistry.Detect(c)
	assert.NoError(t, err)
	assert.Equal(t, grype.Name, conv.Name())
}

func TestSnykFormat(t *testing.T) {
	t.Parallel()
	c, err := parser.GetContainer("../converter/snyk/test.json")
	assert.NoError(t, err)

	conv, err := defaultRegistry.Detect(c)
	assert.NoError(t, err)
	assert.Equal(t, snyk.Name, conv.Name())
}

func TestTrivyFormat(t *testing.T) {
	t.Parallel()
	c, err := parser.GetContainer("../converter/trivy/test.json")
	assert.NoError(t, err)

	conv, err := defaultRegistry.Detect(c)
	assert.NoError(t, err)
	assert.Equal(t, trivy.Name, conv.Name())
}
