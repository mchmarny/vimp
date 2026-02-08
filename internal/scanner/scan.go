package scanner

import (
	"bytes"
	"context"
	"os"
	"os/exec"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// GetSampleScanners returns list of supported scanners.
func GetSampleScanners() []string {
	return GetAllScannerNames()
}

// Scan runs vulnerability scanners against the given image.
func Scan(opt *Options) (*Result, error) {
	return ScanWithContext(context.Background(), opt)
}

// ScanWithContext runs vulnerability scanners with context support.
func ScanWithContext(ctx context.Context, opt *Options) (*Result, error) {
	if opt == nil {
		return nil, errors.New("options are required")
	}

	if err := opt.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid options")
	}

	scanTypes, err := ParseScans(opt.Scans)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing scan types")
	}

	log.Info().Msgf("scanning image %s", opt.Image)

	r := &Result{
		Image: opt.Image,
		Files: make(map[ScanType]string),
	}

	for _, scanType := range scanTypes {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Get scanner from registry
		scanner, ok := GetScanner(scanType.String())
		if !ok {
			log.Warn().Msgf("scanner not found in registry: %s", scanType)
			continue
		}

		if !scanner.IsAvailable() {
			log.Warn().Msgf("skipping scan: %s is not installed", scanType)
			continue
		}

		outputPath, err := scanner.Scan(ctx, opt.Image)
		if err != nil {
			return nil, errors.Wrapf(err, "error running %s scanner", scanType)
		}

		log.Info().Msgf("%s scan complete: %s", scanType, outputPath)

		r.Files[scanType] = outputPath
	}

	return r, nil
}

// ScanWithScanners runs specific scanners by name against the given image.
func ScanWithScanners(ctx context.Context, image string, scannerNames []string) (*ScanResult, error) {
	if image == "" {
		return nil, errors.New("image is required")
	}

	log.Info().Msgf("scanning image %s with scanners: %v", image, scannerNames)

	result := &ScanResult{
		Image: image,
		Files: make(map[string]string),
	}

	for _, name := range scannerNames {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		scanner, ok := GetScanner(name)
		if !ok {
			log.Warn().Msgf("scanner not found: %s", name)
			continue
		}

		if !scanner.IsAvailable() {
			log.Warn().Msgf("skipping scan: %s is not installed", name)
			continue
		}

		outputPath, err := scanner.Scan(ctx, image)
		if err != nil {
			return nil, errors.Wrapf(err, "error running %s scanner", name)
		}

		log.Info().Msgf("%s scan complete: %s", name, outputPath)

		result.Files[name] = outputPath
	}

	return result, nil
}

// ScanResult is the result from ScanWithScanners using string keys.
type ScanResult struct {
	Image string            `json:"image"`
	Files map[string]string `json:"files"`
}

// runCmdWithContext runs a command with context support.
func runCmdWithContext(ctx context.Context, cmd *exec.Cmd, outputPath string) error {
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	// Start the command
	if err := cmd.Start(); err != nil {
		return errors.Wrapf(err, "error starting command: %s", cmd.String())
	}

	// Wait for the command to complete or context to be canceled
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		// Context canceled - kill the process
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return ctx.Err()
	case err := <-done:
		// Command completed
		if _, e := os.Stat(outputPath); errors.Is(e, os.ErrNotExist) {
			// Only error if the file doesn't exist
			// Some scanners (snyk) return non-zero when they find vulnerabilities
			log.Error().Err(err).Msgf("out: %s, err: %s", outb.String(), errb.String())
			return errors.Wrapf(err, "error executing scanner command: %s", cmd.String())
		}
		return nil
	}
}

func isInstalled(c string) bool {
	if _, err := exec.LookPath(c); err != nil {
		return false
	}
	return true
}
