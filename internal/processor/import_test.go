package processor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestImportInput(t *testing.T) {
	t.Parallel()

	o := &ImportOptions{}
	assert.Error(t, o.validate())

	o = &ImportOptions{
		Source: "",
		File:   "../converter/grype/test.json",
		Target: "console://stdout",
	}
	assert.Error(t, o.validate())

	o = &ImportOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe",
		File:   "../converter/grype/test.json",
		Target: "console://stdout",
	}
	assert.NoError(t, o.validate())
}
