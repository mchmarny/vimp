package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/mchmarny/vimp/internal/config"
	"github.com/mchmarny/vimp/internal/converter/trivy"
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
	cmd := t.makeCmd(ctx, image, outputPath)
	return runCmdWithContext(ctx, cmd, outputPath)
}

// ConverterName returns the converter name for trivy output.
func (t *TrivyScanner) ConverterName() string {
	return trivy.Name
}

// makeCmd creates the trivy command.
func (t *TrivyScanner) makeCmd(ctx context.Context, image, outputPath string) *exec.Cmd {
	// Use a unique cache directory to allow concurrent trivy scans.
	// Trivy's file-based cache doesn't support concurrent access to the same directory.
	cacheDir := filepath.Join(os.TempDir(), "vimp-trivy-cache", filepath.Base(filepath.Dir(outputPath)))

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
