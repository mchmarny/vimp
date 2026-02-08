package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mchmarny/vimp/internal/processor"
	"github.com/mchmarny/vimp/internal/scanner"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	c "github.com/urfave/cli/v2"
)

const (
	// defaultScanTimeout is the default timeout for scan operations.
	defaultScanTimeout = 15 * time.Minute
)

var (
	// imageNameRegex validates container image names.
	// Allows: alphanumeric, dots, dashes, underscores, colons, slashes, and @ for digests.
	imageNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]*$`)

	scanCmd = &c.Command{
		Name:  "scan",
		Usage: "scan container image for vulnerabilities",
		Description: `Scan a container image using available vulnerability scanners.

If no --scanner flag is provided, discovers available scanners and prompts
for confirmation before running. Results are saved to ./reports/<image>/<scanner>.json
by default and automatically imported into a local SQLite database.

Examples:
  vimp scan --image alpine:latest
  vimp scan --image ghcr.io/repo/img:v1 --scanner grype --scanner trivy
  vimp scan --image nginx:latest --output ./my-reports --yes`,
		Action: runScan,
		Flags: []c.Flag{
			scanImageFlag,
			scannerFlag,
			outputDirFlag,
			targetFlag,
			yesFlag,
		},
	}
)

func runScan(cc *c.Context) error {
	printVersion(cc)

	image := cc.String(scanImageFlag.Name)
	selectedScanners := cc.StringSlice(scannerFlag.Name)
	outputDir := cc.String(outputDirFlag.Name)
	target := cc.String(targetFlag.Name)
	autoYes := cc.Bool(yesFlag.Name)

	// Validate image name (security: prevent shell injection)
	if err := validateImageName(image); err != nil {
		return errors.Wrap(err, "invalid image name")
	}

	// Determine which scanners to use
	scannersToUse, err := resolveScanners(selectedScanners)
	if err != nil {
		return err
	}

	// If no scanners specified by user, confirm before running
	if len(selectedScanners) == 0 && !autoYes {
		if !confirmScan(scannersToUse, image) {
			log.Info().Msg("scan cancelled by user")
			return nil
		}
	}

	// Create output directory
	sanitizedImage := sanitizeImageName(image)
	reportDir := filepath.Join(outputDir, sanitizedImage)
	if mkdirErr := os.MkdirAll(reportDir, 0755); mkdirErr != nil {
		return errors.Wrapf(mkdirErr, "failed to create output directory: %s", reportDir)
	}

	ctx, cancel := context.WithTimeout(cc.Context, defaultScanTimeout)
	defer cancel()

	// Execute scans
	results, err := executeScanners(ctx, scannersToUse, image, reportDir)
	if err != nil {
		return err
	}

	// Auto-import results into target
	if err := importResults(ctx, results, image, target); err != nil {
		return errors.Wrap(err, "failed to import scan results")
	}

	log.Info().
		Int("scanners", len(results)).
		Str("output", reportDir).
		Msg("scan complete")

	return nil
}

// validateImageName validates the image name for security.
func validateImageName(image string) error {
	if image == "" {
		return errors.New("image name cannot be empty")
	}
	if len(image) > 500 {
		return errors.New("image name too long")
	}
	if !imageNameRegex.MatchString(image) {
		return errors.New("image name contains invalid characters")
	}
	// Additional checks for path traversal
	if strings.Contains(image, "..") {
		return errors.New("image name cannot contain path traversal sequences")
	}
	return nil
}

// resolveScanners determines which scanners to use based on user input.
func resolveScanners(selectedScanners []string) ([]scanner.Scanner, error) {
	if len(selectedScanners) > 0 {
		// User specified scanners - validate and check availability
		var scanners []scanner.Scanner
		for _, name := range selectedScanners {
			s, ok := scanner.GetScanner(name)
			if !ok {
				return nil, errors.Errorf("unknown scanner: %s (supported: %s)",
					name, strings.Join(scanner.GetAllScannerNames(), ", "))
			}
			if !s.IsAvailable() {
				return nil, errors.Errorf("scanner %s is not installed", name)
			}
			scanners = append(scanners, s)
		}
		return scanners, nil
	}

	// No scanners specified - discover available ones
	available := scanner.GetAvailableScanners()
	if len(available) == 0 {
		return nil, errors.Errorf("no scanners found. Install one of: %s",
			strings.Join(scanner.GetAllScannerNames(), ", "))
	}

	return available, nil
}

// confirmScan prompts the user to confirm the scan operation.
func confirmScan(scanners []scanner.Scanner, image string) bool {
	names := make([]string, len(scanners))
	for i, s := range scanners {
		names[i] = s.Name()
	}

	fmt.Printf("\nDiscovered scanners: %s\n", strings.Join(names, ", "))
	fmt.Printf("Image to scan: %s\n", image)
	fmt.Print("Run scan with all discovered scanners? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// sanitizeImageName creates a safe directory name from an image name.
func sanitizeImageName(image string) string {
	// Replace characters that are problematic for file paths
	replacer := strings.NewReplacer(
		"/", "_",
		":", "_",
		"@", "_",
	)
	return replacer.Replace(image)
}

// executeScanners runs all specified scanners against the image.
func executeScanners(ctx context.Context, scanners []scanner.Scanner, image, reportDir string) (map[string]string, error) {
	results := make(map[string]string)

	for _, s := range scanners {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		outputPath := filepath.Join(reportDir, fmt.Sprintf("%s.json", s.Name()))

		log.Info().
			Str("scanner", s.Name()).
			Str("image", image).
			Msg("running scan")

		if err := s.ScanToPath(ctx, image, outputPath); err != nil {
			return nil, errors.Wrapf(err, "scanner %s failed", s.Name())
		}

		log.Info().
			Str("scanner", s.Name()).
			Str("output", outputPath).
			Msg("scan complete")

		results[s.Name()] = outputPath
	}

	return results, nil
}

// importResults imports scan results into the target database.
func importResults(ctx context.Context, results map[string]string, image, target string) error {
	for scannerName, filePath := range results {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		log.Info().
			Str("scanner", scannerName).
			Str("file", filePath).
			Msg("importing results")

		opt := &processor.ImportOptions{
			Source: image,
			File:   filePath,
			Target: target,
		}

		if err := processor.ImportWithContext(ctx, opt); err != nil {
			return errors.Wrapf(err, "failed to import %s results", scannerName)
		}
	}

	return nil
}
