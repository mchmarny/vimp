package scanner

import (
	"context"
	"os/exec"

	"github.com/mchmarny/vimp/internal/config"
	"github.com/mchmarny/vimp/internal/converter/grype"
)

// GrypeScanner implements the Scanner interface for Grype.
type GrypeScanner struct{}

// NewGrypeScanner creates a new Grype scanner.
func NewGrypeScanner() *GrypeScanner {
	return &GrypeScanner{}
}

// Name returns the scanner's identifier.
func (g *GrypeScanner) Name() string {
	return grype.Name
}

// IsAvailable returns true if grype is installed.
func (g *GrypeScanner) IsAvailable() bool {
	return isInstalled(grype.Name)
}

// Scan runs grype against the given image.
func (g *GrypeScanner) Scan(ctx context.Context, image string) (string, error) {
	outputPath := config.GetTempFilePath(grype.Name)
	if err := g.ScanToPath(ctx, image, outputPath); err != nil {
		return "", err
	}
	return outputPath, nil
}

// ScanToPath runs grype and writes output to the specified path.
func (g *GrypeScanner) ScanToPath(ctx context.Context, image, outputPath string) error {
	cmd := g.makeCmd(ctx, image, outputPath)
	return runCmdWithContext(ctx, cmd, outputPath)
}

// ConverterName returns the converter name for grype output.
func (g *GrypeScanner) ConverterName() string {
	return grype.Name
}

// makeCmd creates the grype command.
func (g *GrypeScanner) makeCmd(ctx context.Context, image, outputPath string) *exec.Cmd {
	return exec.CommandContext(ctx, "grype", "-q", "--add-cpes-if-none", "-s", "AllLayers", "-o", "json", "--file", outputPath, image)
}
