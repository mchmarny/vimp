package scanner

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/mchmarny/vimp/internal/config"
	"github.com/mchmarny/vimp/internal/converter/snyk"
)

// SnykScanner implements the Scanner interface for Snyk.
type SnykScanner struct{}

// NewSnykScanner creates a new Snyk scanner.
func NewSnykScanner() *SnykScanner {
	return &SnykScanner{}
}

// Name returns the scanner's identifier.
func (s *SnykScanner) Name() string {
	return snyk.Name
}

// IsAvailable returns true if snyk is installed.
func (s *SnykScanner) IsAvailable() bool {
	return isInstalled(snyk.Name)
}

// Scan runs snyk against the given image.
func (s *SnykScanner) Scan(ctx context.Context, image string) (string, error) {
	outputPath := config.GetTempFilePath(snyk.Name)
	cmd := s.makeCmd(ctx, image, outputPath)

	if err := runCmdWithContext(ctx, cmd, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

// ConverterName returns the converter name for snyk output.
func (s *SnykScanner) ConverterName() string {
	return snyk.Name
}

// makeCmd creates the snyk command.
func (s *SnykScanner) makeCmd(ctx context.Context, image, outputPath string) *exec.Cmd {
	jsonFileOutput := fmt.Sprintf("--json-file-output=%s", outputPath)
	return exec.CommandContext(ctx, "snyk", "container", "test", "--app-vulns", jsonFileOutput, image)
}
