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
		Project: types.TestProjectID,
		Source:  "us-docker.pkg.dev/project/repo/img@sha256:f6efe...",
		File:    "../../../data/snyk.json",
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
		assert.NotEmpty(t, n.LongDescription)
		assert.NotEmpty(t, n.RelatedUrl)
		for _, u := range n.RelatedUrl {
			assert.NotEmpty(t, u.Label)
			assert.NotEmpty(t, u.Url)
		}
		assert.NotEmpty(t, n.CreateTime)
		assert.NotEmpty(t, n.UpdateTime)
		assert.NotNil(t, n.GetVulnerability())
		assert.NotEmpty(t, n.GetVulnerability().CvssScore)
		assert.NotNil(t, n.GetVulnerability().CvssV3)
		assert.NotEmpty(t, n.GetVulnerability().CvssV3.BaseScore)
		assert.NotEmpty(t, n.GetVulnerability().Severity)
		assert.NotEmpty(t, n.GetVulnerability().Details)
		for _, d := range n.GetVulnerability().Details {
			assert.NotEmpty(t, d.AffectedPackage)
			assert.NotNil(t, d.AffectedVersionStart)
			assert.NotEmpty(t, d.AffectedVersionStart.Name)
			assert.NotEmpty(t, d.AffectedVersionStart.Kind)
			assert.NotEmpty(t, d.Description)
			assert.NotEmpty(t, d.SeverityName)
			assert.NotEmpty(t, d.Source)
			assert.NotEmpty(t, d.SourceUpdateTime)
			assert.NotEmpty(t, d.Vendor)
		}
	}
}
