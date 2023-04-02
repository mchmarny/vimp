package processor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInput(t *testing.T) {
	o := &Options{}
	assert.Error(t, o.validate())

	o = &Options{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe",
	}
	assert.Error(t, o.validate())

	o = &Options{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe",
		File:   "../converter/grype/test.json",
	}
	assert.NoError(t, o.validate())

	o = &Options{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe",
		File:   "../converter/grype/test.json",
		CSV:    true,
	}
	assert.Error(t, o.validate())

	f := "test.csv"
	o = &Options{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe",
		File:   "../converter/grype/test.json",
		Output: &f,
		CSV:    true,
	}
	assert.NoError(t, o.validate())
}
