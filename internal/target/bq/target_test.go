package bq

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTargetParsing(t *testing.T) {
	_, err := parseTarget("bq://")
	assert.Error(t, err)

	_, err = parseTarget("bq://project")
	assert.Error(t, err)

	_, err = parseTarget("bq://project.dataset")
	assert.Error(t, err)

	_, err = parseTarget("bq://project.dataset.table.port")
	assert.Error(t, err)

	tr, err := parseTarget("bq://test.vimp.vuls")
	assert.NoError(t, err)
	assert.NotNil(t, t)
	assert.Equal(t, "test", tr.ProjectID)
	assert.Equal(t, "vimp", tr.DatasetID)
	assert.Equal(t, "vuls", tr.TableID)
	assert.Equal(t, importDefaultLocation, tr.Location)
}
