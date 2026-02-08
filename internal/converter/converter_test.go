package converter

import (
	"context"
	"testing"

	"github.com/mchmarny/vimp/internal/converter/grype"
	"github.com/mchmarny/vimp/internal/converter/snyk"
	"github.com/mchmarny/vimp/internal/converter/trivy"
	"github.com/stretchr/testify/assert"
)

func TestRegistry(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	assert.NotNil(t, r)
	assert.Empty(t, r.All())

	r.Register(grype.New())
	assert.Len(t, r.All(), 1)

	names := r.Names()
	assert.Contains(t, names, grype.Name)
}

func TestDefaultRegistry(t *testing.T) {
	t.Parallel()

	r := DefaultRegistry()
	assert.NotNil(t, r)
	assert.Len(t, r.All(), 6)

	names := r.Names()
	assert.Contains(t, names, grype.Name)
	assert.Contains(t, names, trivy.Name)
	assert.Contains(t, names, snyk.Name)
	assert.Contains(t, names, "clair")
	assert.Contains(t, names, "osv")
	assert.Contains(t, names, "anchore")
}

func TestRegistryGet(t *testing.T) {
	t.Parallel()

	r := DefaultRegistry()

	conv, ok := r.Get(grype.Name)
	assert.True(t, ok)
	assert.Equal(t, grype.Name, conv.Name())

	conv, ok = r.Get("nonexistent")
	assert.False(t, ok)
	assert.Nil(t, conv)
}

func TestRegistryDetect(t *testing.T) {
	t.Parallel()

	r := DefaultRegistry()

	// nil container
	conv, err := r.Detect(nil)
	assert.Error(t, err)
	assert.Nil(t, conv)
}

func TestConverterCanHandle(t *testing.T) {
	t.Parallel()

	grypeConv := grype.New()
	trivyConv := trivy.New()
	snykConv := snyk.New()

	// nil container should return false
	assert.False(t, grypeConv.CanHandle(nil))
	assert.False(t, trivyConv.CanHandle(nil))
	assert.False(t, snykConv.CanHandle(nil))
}

func TestConverterConvertNilContainer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	grypeConv := grype.New()
	trivyConv := trivy.New()
	snykConv := snyk.New()

	// nil container should return error
	_, err := grypeConv.Convert(ctx, nil)
	assert.Error(t, err)

	_, err = trivyConv.Convert(ctx, nil)
	assert.Error(t, err)

	_, err = snykConv.Convert(ctx, nil)
	assert.Error(t, err)
}
