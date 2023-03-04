package snyk

import (
	"context"
	"testing"

	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestConverter(t *testing.T) {
	opt := &types.ImportOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:   "../../../data/grype.json",
		Format: types.SourceFormatGrypeJSON,
	}
	s, err := src.NewSource(opt)
	assert.NoError(t, err)
	assert.NotNil(t, s)

	list, err := Convert(context.TODO(), s)
	assert.NoError(t, err)
	assert.NotNil(t, list)

	for i, o := range list {
		assert.NotEmptyf(t, o.Vulnerability, "item: %d", i)
		assert.NotNilf(t, o.Vulnerability.PackageIssue, "item: %d", i)
		assert.NotEmptyf(t, o.Vulnerability.Severity, "item: %d", i)
		assert.NotEmptyf(t, o.Vulnerability.Type, "item: %d", i)
		// assert.NotNilf(t, v.CvssV2, "item: %d", i)
		// assert.NotNilf(t, v.Cvssv3, "item: %d", i)
	}
}
