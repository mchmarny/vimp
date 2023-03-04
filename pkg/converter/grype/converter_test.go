package grype

import (
	"context"
	"testing"

	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/stretchr/testify/assert"
)

func TestConverter(t *testing.T) {
	s, err := src.NewSource("../../../data/grype-json.json")
	assert.NoError(t, err)
	assert.NotNil(t, s)

	list, err := Convert(context.TODO(), s)
	assert.NoError(t, err)
	assert.NotNil(t, list)

	for i, v := range list {
		assert.NotEmptyf(t, v.EffectiveSeverity, "item: %d", i)
		assert.NotEmptyf(t, v.Severity, "item: %d", i)
		assert.NotEmptyf(t, v.Type, "item: %d", i)
		// assert.NotNilf(t, v.CvssV2, "item: %d", i)
		// assert.NotNilf(t, v.Cvssv3, "item: %d", i)
	}
}
