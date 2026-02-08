package scanner

import (
	"context"
	"os/exec"

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
	cmd := t.makeCmd(ctx, image, outputPath)

	if err := runCmdWithContext(ctx, cmd, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

// ConverterName returns the converter name for trivy output.
func (t *TrivyScanner) ConverterName() string {
	return trivy.Name
}

// makeCmd creates the trivy command.
func (t *TrivyScanner) makeCmd(ctx context.Context, image, outputPath string) *exec.Cmd {
	return exec.CommandContext(ctx, "trivy", "image", "--quiet", "--security-checks", "vuln", "--format", "json", "--no-progress", "--output", outputPath, image)
}
