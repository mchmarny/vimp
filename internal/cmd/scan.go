package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mchmarny/vimp/internal/processor"
	"github.com/mchmarny/vimp/internal/registry"
	"github.com/mchmarny/vimp/internal/scanner"
	"github.com/pkg/errors"
	c "github.com/urfave/cli/v3"
	"golang.org/x/sync/errgroup"
)

const (
	// defaultScanTimeout is the default timeout for scan operations.
	defaultScanTimeout = 15 * time.Minute

	// maxConcurrency limits parallel scan operations.
	maxConcurrency = 10
)

var (
	// imageNameRegex validates container image names.
	// Allows: alphanumeric, dots, dashes, underscores, colons, slashes, and @ for digests.
	imageNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]*$`)

	scanCmd = &c.Command{
		Name:     "scan",
		Category: categoryFunctional,
		Usage:    "scan container image for vulnerabilities",
		Description: `Scan a container image using available vulnerability scanners.

If no --scanner flag is provided, discovers available scanners and prompts
for confirmation before running. Results are saved to ./reports/<image>/<scanner>.json
by default and automatically imported into a local SQLite database.

Use --disco to discover and scan recent tags from the registry.

Examples:
  vimp scan --image alpine:latest
  vimp scan --image ghcr.io/repo/img:v1 --scanner grype --scanner trivy
  vimp scan --image nginx:latest --output ./my-reports --yes
  vimp scan --image alpine --disco --tags 3 --yes`,
		Action: runScan,
		Flags: []c.Flag{
			scanImageFlag,
			scannerFlag,
			outputDirFlag,
			targetFlag,
			yesFlag,
			scanOnlyFlag,
			discoFlag,
			tagsFlag,
		},
	}
)

// scanResult captures the outcome of a single scan operation.
type scanResult struct {
	Image   string
	Scanner string
	Path    string
	Error   error
}

func runScan(ctx context.Context, cmd *c.Command) error {
	image := cmd.String(scanImageFlag.Name)
	selectedScanners := cmd.StringSlice(scannerFlag.Name)
	outputDir := cmd.String(outputDirFlag.Name)
	target := cmd.String(targetFlag.Name)
	autoYes := cmd.Bool(yesFlag.Name)
	scanOnly := cmd.Bool(scanOnlyFlag.Name)
	disco := cmd.Bool(discoFlag.Name)
	tagsCount := cmd.Int(tagsFlag.Name)

	slog.Debug("scan command started",
		"image", image,
		"disco", disco,
		"tagsCount", tagsCount,
		"scanOnly", scanOnly,
		"outputDir", outputDir,
	)

	// Validate image name (security: prevent shell injection)
	if err := validateImageName(image); err != nil {
		return errors.Wrap(err, "invalid image name")
	}

	// Validate disco flags
	if tagsCount < 1 || tagsCount > 20 {
		return errors.New("--tags must be between 1 and 20")
	}

	// Determine which scanners to use
	slog.Debug("resolving scanners", "selected", selectedScanners)
	scannersToUse, err := resolveScanners(selectedScanners)
	if err != nil {
		return err
	}
	slog.Debug("resolved scanners", "count", len(scannersToUse))

	// Resolve images to scan
	var images []string
	if disco {
		slog.Info("discovering tags", "image", image, "count", tagsCount)
		tags, discoErr := registry.DiscoverTags(ctx, image, tagsCount)
		if discoErr != nil {
			return errors.Wrap(discoErr, "failed to discover tags")
		}
		images, err = registry.BuildImageURIs(image, tags)
		if err != nil {
			return errors.Wrap(err, "failed to build image URIs")
		}
		slog.Info("discovered tags", "count", len(images), "tags", tags)
	} else {
		images = []string{image}
	}

	// If no scanners specified by user, confirm before running
	if len(selectedScanners) == 0 && !autoYes {
		if !confirmScanMultiple(scannersToUse, images) {
			slog.Info("scan cancelled by user")
			return nil
		}
	}

	ctx, cancel := context.WithTimeout(ctx, defaultScanTimeout)
	defer cancel()

	totalOps := len(images) * len(scannersToUse)
	slog.Info("starting scans",
		"images", len(images),
		"scanners", len(scannersToUse),
		"operations", totalOps,
	)
	slog.Debug("concurrent scan config", "maxConcurrency", maxConcurrency)

	// Execute scans concurrently
	results := executeConcurrentScans(ctx, images, scannersToUse, outputDir, target, scanOnly)

	// Report results
	var failed, succeeded int
	for _, r := range results {
		if r.Error != nil {
			failed++
			slog.Error("scan/import failed", "image", r.Image, "scanner", r.Scanner, "error", r.Error)
		} else {
			succeeded++
			slog.Info("scan complete", "image", r.Image, "scanner", r.Scanner, "output", r.Path)
		}
	}

	slog.Info("scan summary", "succeeded", succeeded, "failed", failed, "total", len(results))

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

// confirmScanMultiple prompts the user to confirm scanning multiple images.
func confirmScanMultiple(scanners []scanner.Scanner, images []string) bool {
	names := make([]string, len(scanners))
	for i, s := range scanners {
		names[i] = s.Name()
	}

	fmt.Printf("\nDiscovered scanners: %s\n", strings.Join(names, ", "))
	fmt.Printf("Images to scan (%d):\n", len(images))
	for _, img := range images {
		fmt.Printf("  - %s\n", img)
	}
	fmt.Printf("Total operations: %d\n", len(images)*len(scanners))
	fmt.Print("Run scans? [y/N]: ")

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

// buildOutputPath creates the output path for a scan result.
func buildOutputPath(outputDir, image, scannerName string) string {
	sanitized := sanitizeImageName(image)
	return filepath.Join(outputDir, sanitized, fmt.Sprintf("%s.json", scannerName))
}

// executeConcurrentScans runs all (image × scanner) combinations concurrently.
func executeConcurrentScans(ctx context.Context, images []string, scanners []scanner.Scanner,
	outputDir, target string, scanOnly bool) []scanResult {

	var (
		mu      sync.Mutex
		results []scanResult
	)

	// Semaphore for limiting concurrency
	sem := make(chan struct{}, maxConcurrency)
	g, ctx := errgroup.WithContext(ctx)

	for _, img := range images {
		for _, s := range scanners {
			g.Go(func() error {
				// Acquire semaphore
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return nil // Don't block on canceled context
				}

				result := scanResult{Image: img, Scanner: s.Name()}
				outputPath := buildOutputPath(outputDir, img, s.Name())

				slog.Debug("acquired semaphore", "scanner", s.Name(), "image", img)

				// Ensure output directory exists
				if mkdirErr := os.MkdirAll(filepath.Dir(outputPath), 0755); mkdirErr != nil {
					result.Error = errors.Wrapf(mkdirErr, "failed to create output directory")
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
					return nil
				}

				slog.Info("running scan", "scanner", s.Name(), "image", img)
				slog.Debug("scan output path", "path", outputPath)

				// Scan
				if err := s.ScanToPath(ctx, img, outputPath); err != nil {
					slog.Debug("scan failed", "scanner", s.Name(), "image", img, "error", err)
					result.Error = errors.Wrapf(err, "scan failed: %s/%s", s.Name(), img)
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
					return nil // Don't fail entire group
				}

				slog.Debug("scan succeeded", "scanner", s.Name(), "image", img)
				result.Path = outputPath

				// Import (unless scan-only)
				if !scanOnly && target != "" {
					slog.Debug("importing results", "scanner", s.Name(), "image", img, "target", target)
					opt := &processor.ImportOptions{
						Source: img,
						File:   outputPath,
						Target: target,
					}
					if err := processor.ImportWithContext(ctx, opt); err != nil {
						slog.Debug("import failed", "scanner", s.Name(), "image", img, "error", err)
						result.Error = errors.Wrapf(err, "import failed: %s/%s", s.Name(), img)
					} else {
						slog.Debug("import succeeded", "scanner", s.Name(), "image", img)
					}
				}

				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				return nil
			})
		}
	}

	_ = g.Wait() // Errors captured in results
	return results
}
