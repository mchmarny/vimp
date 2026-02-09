package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

func setupTestServer(t *testing.T) (*Server, string) {
	t.Helper()

	// Create a temp file for the test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create and setup the database
	db, err := sql.Open("sqlite", dbPath)
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

	// Insert test data
	now := time.Now().Format(time.RFC3339)
	testData := []struct {
		image, digest, source, processed, exposure, pkg, version, severity string
		score                                                              float64
		fixed                                                              int
	}{
		{"docker.io/library/alpine", "sha256:abc123", "grype", now, "CVE-2024-0001", "openssl", "1.1.1", "critical", 9.8, 1},
		{"docker.io/library/alpine", "sha256:abc123", "grype", now, "CVE-2024-0002", "curl", "7.0.0", "high", 7.5, 0},
		{"ghcr.io/user/app", "sha256:ghi789", "trivy", now, "CVE-2024-0003", "nginx", "1.0.0", "low", 3.0, 0},
	}

	stmt, err := db.Prepare(`INSERT INTO vul VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	require.NoError(t, err)
	for _, d := range testData {
		_, execErr := stmt.Exec(d.image, d.digest, d.source, d.processed, d.exposure, d.pkg, d.version, d.severity, d.score, d.fixed)
		require.NoError(t, execErr)
	}
	stmt.Close()
	db.Close()

	// Create server
	cfg := &Config{
		Port:    0, // Will be assigned
		Target:  "sqlite://" + dbPath,
		Version: "test-version",
	}

	srv, err := New(cfg)
	require.NoError(t, err)

	return srv, dbPath
}

func TestNewServer(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer srv.Close()
	defer os.Remove(dbPath)

	assert.NotNil(t, srv)
	assert.NotNil(t, srv.db)
	assert.NotNil(t, srv.queries)
	assert.NotNil(t, srv.tmpl)
	assert.NotNil(t, srv.mux)
}

func TestNewServer_InvalidConfig(t *testing.T) {
	// Nil config
	_, err := New(nil)
	assert.Error(t, err)

	// Missing target
	_, err = New(&Config{Port: 8080})
	assert.Error(t, err)

	// Invalid database path
	_, err = New(&Config{Port: 8080, Target: "sqlite:///nonexistent/path/db.db"})
	assert.Error(t, err)
}

func TestHandleDashboard(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer srv.Close()
	defer os.Remove(dbPath)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Check that the page contains expected elements
	assert.Contains(t, string(body), "Dashboard")
	assert.Contains(t, string(body), "test-version")
}

func TestHandleImages(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer srv.Close()
	defer os.Remove(dbPath)

	req := httptest.NewRequest(http.MethodGet, "/images", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Contains(t, string(body), "Images")
	assert.Contains(t, string(body), "alpine")
}

func TestHandleImages_Search(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer srv.Close()
	defer os.Remove(dbPath)

	req := httptest.NewRequest(http.MethodGet, "/images?search=alpine", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Contains(t, string(body), "alpine")
	assert.NotContains(t, string(body), "ghcr.io")
}

func TestHandleImageDetail(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer srv.Close()
	defer os.Remove(dbPath)

	req := httptest.NewRequest(http.MethodGet, "/images/docker.io/library/alpine", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Contains(t, string(body), "alpine")
	assert.Contains(t, string(body), "sha256:abc123")
}

func TestHandleExposures(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer srv.Close()
	defer os.Remove(dbPath)

	req := httptest.NewRequest(http.MethodGet, "/images/docker.io/library/alpine?digest=sha256:abc123", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Contains(t, string(body), "Exposures")
	assert.Contains(t, string(body), "CVE-2024-0001")
}

func TestHandleAPIStats(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer srv.Close()
	defer os.Remove(dbPath)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	var stats DashboardStats
	err := json.NewDecoder(resp.Body).Decode(&stats)
	require.NoError(t, err)

	assert.Equal(t, 2, stats.TotalImages)
	assert.Equal(t, 2, stats.TotalDigests)
}

func TestHandleAPIImages(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer srv.Close()
	defer os.Remove(dbPath)

	req := httptest.NewRequest(http.MethodGet, "/api/images", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	var images []*RecentImage
	err := json.NewDecoder(resp.Body).Decode(&images)
	require.NoError(t, err)

	assert.Len(t, images, 2)
}

func TestHandleAPITimeSeries(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer srv.Close()
	defer os.Remove(dbPath)

	req := httptest.NewRequest(http.MethodGet, "/api/timeseries/docker.io/library/alpine", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	var series []*TimeSeriesPoint
	err := json.NewDecoder(resp.Body).Decode(&series)
	require.NoError(t, err)

	assert.True(t, len(series) > 0)
}

func TestHandlePartialImages_HTMX(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer srv.Close()
	defer os.Remove(dbPath)

	req := httptest.NewRequest(http.MethodGet, "/partials/images", nil)
	req.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Should return just the table, not the full page
	assert.Contains(t, string(body), "alpine")
	assert.NotContains(t, string(body), "<!DOCTYPE html>")
}

func TestStaticFiles(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer srv.Close()
	defer os.Remove(dbPath)

	tests := []struct {
		path        string
		contentType string
	}{
		{"/static/style.css", "text/css"},
		{"/static/htmx.min.js", "text/javascript"},
		{"/static/chart.min.js", "text/javascript"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			srv.mux.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			// Static files are served
			body, _ := io.ReadAll(resp.Body)
			assert.True(t, len(body) > 0)
		})
	}
}

func TestServerStartAndShutdown(t *testing.T) {
	srv, dbPath := setupTestServer(t)
	defer os.Remove(dbPath)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for context to cancel (graceful shutdown)
	select {
	case err := <-errCh:
		// Should be nil or context canceled
		assert.True(t, err == nil || errors.Is(err, context.DeadlineExceeded))
	case <-time.After(1 * time.Second):
		t.Fatal("server did not shut down in time")
	}

	srv.Close()
}
