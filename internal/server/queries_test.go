package server

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	// Create schema
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS vul (
			image TEXT NOT NULL,
			digest TEXT NOT NULL,
			source TEXT NOT NULL,
			processed TEXT NOT NULL,
			exposure TEXT NOT NULL,
			package TEXT NOT NULL,
			version TEXT NOT NULL,
			severity TEXT NOT NULL,
			score REAL NOT NULL,
			fixed NUMERIC NOT NULL,
			PRIMARY KEY (image, digest, source, exposure, package, version)
		)
	`)
	require.NoError(t, err)

	return db
}

func insertTestData(t *testing.T, db *sql.DB) {
	t.Helper()

	now := time.Now().Format(time.RFC3339)
	yesterday := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)

	testData := []struct {
		image, digest, source, processed, exposure, pkg, version, severity string
		score                                                              float64
		fixed                                                              int
	}{
		{"docker.io/library/alpine", "sha256:abc123", "grype", now, "CVE-2024-0001", "openssl", "1.1.1", "critical", 9.8, 1},
		{"docker.io/library/alpine", "sha256:abc123", "grype", now, "CVE-2024-0002", "curl", "7.0.0", "high", 7.5, 0},
		{"docker.io/library/alpine", "sha256:abc123", "trivy", now, "CVE-2024-0001", "openssl", "1.1.1", "critical", 9.8, 1},
		{"docker.io/library/alpine", "sha256:def456", "grype", yesterday, "CVE-2024-0003", "zlib", "1.2.0", "medium", 5.5, 0},
		{"ghcr.io/user/app", "sha256:ghi789", "grype", now, "CVE-2024-0004", "nginx", "1.0.0", "low", 3.0, 0},
		{"ghcr.io/user/app", "sha256:ghi789", "trivy", now, "CVE-2024-0004", "nginx", "1.0.0", "low", 3.1, 0},
	}

	stmt, err := db.Prepare(`INSERT INTO vul (image, digest, source, processed, exposure, package, version, severity, score, fixed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	require.NoError(t, err)
	defer stmt.Close()

	for _, d := range testData {
		_, err := stmt.Exec(d.image, d.digest, d.source, d.processed, d.exposure, d.pkg, d.version, d.severity, d.score, d.fixed)
		require.NoError(t, err)
	}
}

func TestGetDashboardStats(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	insertTestData(t, db)

	q := NewQueries(db)
	ctx := context.Background()

	stats, err := q.GetDashboardStats(ctx)
	require.NoError(t, err)

	assert.Equal(t, 2, stats.TotalImages)
	assert.Equal(t, 3, stats.TotalDigests)
	assert.Equal(t, 4, stats.TotalExposures)
	assert.True(t, stats.CriticalCount > 0)
	assert.True(t, stats.HighCount > 0)
	assert.True(t, stats.MediumCount > 0)
	assert.True(t, stats.LowCount > 0)
	assert.True(t, stats.FixableCount > 0)
	assert.True(t, stats.UnfixableCount > 0)
}

func TestGetDashboardStats_EmptyDB(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	q := NewQueries(db)
	ctx := context.Background()

	stats, err := q.GetDashboardStats(ctx)
	require.NoError(t, err)

	assert.Equal(t, 0, stats.TotalImages)
	assert.Equal(t, 0, stats.TotalDigests)
	assert.Equal(t, 0, stats.TotalExposures)
}

func TestGetRegistryStats(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	insertTestData(t, db)

	q := NewQueries(db)
	ctx := context.Background()

	stats, err := q.GetRegistryStats(ctx, 10)
	require.NoError(t, err)

	assert.Len(t, stats, 2)
	// Check that registries are returned
	registries := make(map[string]bool)
	for _, s := range stats {
		registries[s.Registry] = true
		assert.True(t, s.ImageCount > 0)
	}
	assert.True(t, registries["docker.io"])
	assert.True(t, registries["ghcr.io"])
}

func TestGetRecentImages(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	insertTestData(t, db)

	q := NewQueries(db)
	ctx := context.Background()

	images, err := q.GetRecentImages(ctx, 10)
	require.NoError(t, err)

	assert.Len(t, images, 3) // 3 unique image+digest combinations
	// First result should be most recent
	assert.False(t, images[0].LastScan.IsZero())
	for _, img := range images {
		assert.NotEmpty(t, img.Image)
		assert.NotEmpty(t, img.Digest)
		assert.True(t, img.Exposures > 0)
	}
}

func TestSearchImages(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	insertTestData(t, db)

	q := NewQueries(db)
	ctx := context.Background()

	// Search for alpine
	images, err := q.SearchImages(ctx, "alpine", 10)
	require.NoError(t, err)
	assert.Len(t, images, 2) // Two digests for alpine

	// Search for ghcr
	images, err = q.SearchImages(ctx, "ghcr", 10)
	require.NoError(t, err)
	assert.Len(t, images, 1)

	// Search for non-existent
	images, err = q.SearchImages(ctx, "nonexistent", 10)
	require.NoError(t, err)
	assert.Len(t, images, 0)
}

func TestGetImageDetail(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	insertTestData(t, db)

	q := NewQueries(db)
	ctx := context.Background()

	detail, err := q.GetImageDetail(ctx, "docker.io/library/alpine")
	require.NoError(t, err)

	assert.Equal(t, "docker.io/library/alpine", detail.Image)
	assert.Len(t, detail.Digests, 2) // Two digests for alpine
	for _, d := range detail.Digests {
		assert.NotEmpty(t, d.Digest)
		assert.True(t, d.Exposures > 0)
		assert.NotEmpty(t, d.Sources)
	}
}

func TestGetExposures(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	insertTestData(t, db)

	q := NewQueries(db)
	ctx := context.Background()

	exposures, err := q.GetExposures(ctx, "docker.io/library/alpine", "sha256:abc123")
	require.NoError(t, err)

	assert.True(t, len(exposures) > 0)
	// Should be sorted by severity (critical first)
	assert.Equal(t, "critical", exposures[0].Severity)
	for _, e := range exposures {
		assert.NotEmpty(t, e.Exposure)
		assert.NotEmpty(t, e.Package)
		assert.NotEmpty(t, e.Version)
	}
}

func TestGetTimeSeries(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	insertTestData(t, db)

	q := NewQueries(db)
	ctx := context.Background()

	series, err := q.GetTimeSeries(ctx, "docker.io/library/alpine")
	require.NoError(t, err)

	assert.True(t, len(series) > 0)
	for _, point := range series {
		assert.NotEmpty(t, point.Date)
		assert.True(t, point.Total > 0)
	}
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		input    string
		expected bool // whether parsing should succeed (non-zero time)
	}{
		{"2024-01-15T10:30:00Z", true},
		{"2024-01-15T10:30:00+00:00", true},
		{"2024-01-15T10:30:00", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		result := parseTime(tt.input)
		if tt.expected {
			assert.False(t, result.IsZero(), "expected non-zero time for input: %s", tt.input)
		} else {
			assert.True(t, result.IsZero(), "expected zero time for input: %s", tt.input)
		}
	}
}
