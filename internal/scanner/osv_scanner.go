package scanner

import (
	"context"
	"os/exec"
	"strings"
	"sync"

	"github.com/mchmarny/vimp/internal/config"
	"github.com/mchmarny/vimp/internal/converter/osv"
	"github.com/pkg/errors"
)

const osvScannerCmd = "osv-scanner"

// OSVScanner implements the Scanner interface for OSV-Scanner.
// Note: OSV-Scanner primarily scans lockfiles and SBOMs, not container images directly.
// Direct container image scanning support varies by osv-scanner version.
type OSVScanner struct {
	once            sync.Once
	dockerSupported bool
}

// NewOSVScanner creates a new OSV scanner.
func NewOSVScanner() *OSVScanner {
	return &OSVScanner{}
}

// Name returns the scanner's identifier.
func (o *OSVScanner) Name() string {
	return osv.Name
}

// IsAvailable returns true if osv-scanner is installed and supports docker scanning.
func (o *OSVScanner) IsAvailable() bool {
	if !isInstalled(osvScannerCmd) {
		return false
	}

	// Check if docker flag is supported (cache the result thread-safely)
	o.once.Do(func() {
		o.dockerSupported = o.checkDockerSupport()
	})
	return o.dockerSupported
}

// checkDockerSupport checks if osv-scanner supports the --docker flag.
func (o *OSVScanner) checkDockerSupport() bool {
	cmd := exec.Command(osvScannerCmd, "--help") //nolint:noctx // No context available in init check
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "--docker")
}

// Scan runs osv-scanner against the given image.
func (o *OSVScanner) Scan(ctx context.Context, image string) (string, error) {
	if !o.IsAvailable() {
		return "", errors.New("osv-scanner docker scanning is not available")
	}

	outputPath := config.GetTempFilePath(osv.Name)
	cmd := o.makeCmd(ctx, image, outputPath)

	if err := runCmdWithContext(ctx, cmd, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

// ConverterName returns the converter name for osv output.
func (o *OSVScanner) ConverterName() string {
	return osv.Name
}

// makeCmd creates the osv-scanner command.
func (o *OSVScanner) makeCmd(ctx context.Context, image, outputPath string) *exec.Cmd {
	return exec.CommandContext(ctx, osvScannerCmd, "--format", "json", "--output", outputPath, "--docker", image)
}
