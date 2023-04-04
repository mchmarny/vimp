package target

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTarget(t *testing.T) {
	t.Parallel()

	_, err := GetImporter("redis://localhost:6379")
	assert.Error(t, err)

	_, err = GetImporter("bq://project.dataset.table")
	assert.NoError(t, err)

	_, err = GetImporter("file://path/to/file")
	assert.NoError(t, err)

	_, err = GetImporter("console://stdout")
	assert.NoError(t, err)
}
