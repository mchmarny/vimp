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
	assert.Error(t, o.validate())

	o = &Options{
		Source: "",
		File:   "../converter/grype/test.json",
		Target: "console://stdout",
	}
	assert.Error(t, o.validate())

	o = &Options{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe",
		File:   "../converter/grype/test.json",
		Target: "",
	}
	assert.Error(t, o.validate())

	o = &Options{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe",
		File:   "../converter/grype/test.json",
		Target: "console://stdout",
	}
	assert.NoError(t, o.validate())
}
