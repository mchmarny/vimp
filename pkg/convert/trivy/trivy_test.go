package trivy

import (
	"context"
	"testing"

	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestTrivyConverter(t *testing.T) {
	opt := &types.ImportOptions{
		Project: types.TestProjectID,
		Source:  "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:    "../../../data/trivy.json",
		Format:  types.SourceFormatSnykJSON,
	}
	s, err := src.NewSource(opt)
	assert.NoError(t, err)
	assert.NotNil(t, s)

	list, err := Convert(context.TODO(), s)
	assert.NoErrorf(t, err, "failed to convert: %v", err)
	assert.NotNil(t, list)

	for id, nocc := range list {
		n := nocc.Note
		assert.NotEmpty(t, id)
		assert.NotEmpty(t, n.Name)
		assert.NotEmpty(t, n.ShortDescription)
		assert.NotEmpty(t, n.RelatedUrl)
		for _, u := range n.RelatedUrl {
			assert.NotEmpty(t, u.Label)
			assert.NotEmpty(t, u.Url)
		}
		assert.NotNil(t, n.GetVulnerability())
		assert.NotEmpty(t, n.GetVulnerability().CvssScore)
		assert.NotNil(t, n.GetVulnerability().CvssVersion)
		assert.NotEmpty(t, n.GetVulnerability().Severity)
		assert.NotEmpty(t, n.GetVulnerability().Details)
		for _, d := range n.GetVulnerability().Details {
			assert.NotEmpty(t, d.AffectedPackage)
			assert.NotEmpty(t, d.AffectedCpeUri)
		}
	}
}
