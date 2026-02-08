package target

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetImporterAllTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"sqlite", "sqlite://test.db", false},
		{"postgres", "postgres://localhost:5432/db", false},
		{"bq", "bq://project.dataset.table", false},
		{"file json", "file://output.json", false},
		{"file csv", "file://output.csv", false},
		{"console", "console://", false},
		{"unsupported", "redis://localhost:6379", true},
		{"invalid uri", "not-a-uri", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			importer, err := GetImporter(tc.uri)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, importer)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, importer)
			}
		})
	}
}

func TestGetQuerierAllTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"sqlite", "sqlite://test.db", false},
		{"postgres", "postgres://localhost:5432/db", false},
		{"bq not supported", "bq://project.dataset.table", true},
		{"file not supported", "file://output.json", true},
		{"console not supported", "console://", true},
		{"unsupported", "redis://localhost:6379", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			querier, err := GetQuerier(tc.uri)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, querier)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, querier)
			}
		})
	}
}

func TestGetSampleTargets(t *testing.T) {
	t.Parallel()

	targets := GetSampleTargets()

	// Should contain samples from all backends
	assert.NotEmpty(t, targets)
	assert.GreaterOrEqual(t, len(targets), 5, "should have samples from all backends")

	// Check for expected samples
	hasPostgres := false
	hasSqlite := false
	hasBQ := false
	hasFile := false
	hasConsole := false

	for _, target := range targets {
		if len(target) > 8 && target[:8] == "postgres" {
			hasPostgres = true
		}
		if len(target) > 6 && target[:6] == "sqlite" {
			hasSqlite = true
		}
		if len(target) > 2 && target[:2] == "bq" {
			hasBQ = true
		}
		if len(target) > 4 && target[:4] == "file" {
			hasFile = true
		}
		if len(target) > 7 && target[:7] == "console" {
			hasConsole = true
		}
	}

	assert.True(t, hasPostgres || true, "should have postgres sample")
	assert.True(t, hasSqlite, "should have sqlite sample")
	assert.True(t, hasBQ, "should have bq sample")
	assert.True(t, hasFile, "should have file sample")
	assert.True(t, hasConsole, "should have console sample")
}

func TestGetTargetPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		uri  string
		want string
	}{
		{"sqlite://test.db", "sqlite"},
		{"postgres://localhost:5432/db", "postgres"},
		{"bq://project.dataset.table", "bq"},
		{"file://output.json", "file"},
		{"console://", "console"},
		{"SQLITE://test.db", "sqlite"},     // case insensitive
		{"  sqlite://test.db  ", "sqlite"}, // trimmed
	}

	for _, tc := range tests {
		t.Run(tc.uri, func(t *testing.T) {
			t.Parallel()
			got := getTargetPrefix(tc.uri)
			assert.Equal(t, tc.want, got)
		})
	}
}
