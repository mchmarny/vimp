package scanner

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/mchmarny/vimp/internal/config"
	"github.com/mchmarny/vimp/internal/converter/trivy"
)

const (
	// trivyCacheBaseDir is the base directory for trivy cache.
	trivyCacheBaseDir = "vimp-trivy-cache"

	// staleCacheAge is the age after which a cache directory is considered stale.
	staleCacheAge = 2 * time.Hour
)

// TrivyScanner implements the Scanner interface for Trivy.
type TrivyScanner struct{}

// NewTrivyScanner creates a new Trivy scanner.
func NewTrivyScanner() *TrivyScanner {
	return &TrivyScanner{}
}

// Name returns the scanner's identifier.
func (t *TrivyScanner) Name() string {
	return trivy.Name
}

// IsAvailable returns true if trivy is installed.
func (t *TrivyScanner) IsAvailable() bool {
	return isInstalled(trivy.Name)
}

// Scan runs trivy against the given image.
func (t *TrivyScanner) Scan(ctx context.Context, image string) (string, error) {
	outputPath := config.GetTempFilePath(trivy.Name)
	if err := t.ScanToPath(ctx, image, outputPath); err != nil {
		return "", err
	}
	return outputPath, nil
}

// ScanToPath runs trivy and writes output to the specified path.
func (t *TrivyScanner) ScanToPath(ctx context.Context, image, outputPath string) error {
	cacheDir := t.getCacheDir(outputPath)

	// Clean stale caches before starting
	cleanStaleTrivyCaches()

	// Remove this specific cache dir if it exists (stale lock)
	if err := os.RemoveAll(cacheDir); err != nil {
		slog.Debug("failed to clean trivy cache dir", "path", cacheDir, "error", err)
	}

	cmd := t.makeCmd(ctx, image, outputPath, cacheDir)
	err := runCmdWithContext(ctx, cmd, outputPath)

	// Clean up cache after scan (successful or not) to avoid stale locks
	if cleanErr := os.RemoveAll(cacheDir); cleanErr != nil {
		slog.Debug("failed to clean trivy cache after scan", "path", cacheDir, "error", cleanErr)
	}

	return err
}

// ConverterName returns the converter name for trivy output.
func (t *TrivyScanner) ConverterName() string {
	return trivy.Name
}

// getCacheDir returns the cache directory path for a given output path.
func (t *TrivyScanner) getCacheDir(outputPath string) string {
	return filepath.Join(os.TempDir(), trivyCacheBaseDir, filepath.Base(filepath.Dir(outputPath)))
}

// makeCmd creates the trivy command.
func (t *TrivyScanner) makeCmd(ctx context.Context, image, outputPath, cacheDir string) *exec.Cmd {
	return exec.CommandContext(ctx, "trivy", "image",
		"--quiet",
		"--security-checks", "vuln",
		"--format", "json",
		"--no-progress",
		"--cache-dir", cacheDir,
		"--output", outputPath,
		image,
	)
}

// cleanStaleTrivyCaches removes trivy cache directories older than staleCacheAge.
func cleanStaleTrivyCaches() {
	baseDir := filepath.Join(os.TempDir(), trivyCacheBaseDir)

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return // Directory doesn't exist or can't be read
	}

	cutoff := time.Now().Add(-staleCacheAge)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			path := filepath.Join(baseDir, entry.Name())
			if err := os.RemoveAll(path); err != nil {
				slog.Debug("failed to remove stale trivy cache", "path", path, "error", err)
			} else {
				slog.Debug("removed stale trivy cache", "path", path, "age", time.Since(info.ModTime()))
			}
		}
	}
}
