package processor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestImportInput(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	o := &ImportOptions{}
	assert.Error(t, o.validate(ctx))

	o = &ImportOptions{
		Source: "",
		File:   "../converter/grype/test.json",
		Target: "console://stdout",
	}
	assert.Error(t, o.validate(ctx))

	o = &ImportOptions{
		Source: "us-docker.pkg.dev/project/repo/img@sha256:f6efe",
		File:   "../converter/grype/test.json",
		Target: "console://stdout",
	}
	assert.NoError(t, o.validate(ctx))
}
