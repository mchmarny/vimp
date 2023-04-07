package scanner

import (
	"bytes"
	"os"
	"os/exec"

	"github.com/mchmarny/vimp/internal/config"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// GetSampleScanners returns list of supported scanners.
func GetSampleScanners() []string {
	return []string{
		Grype.String(),
		Snyk.String(),
		Trivy.String(),
	}
}

// GetVulnerabilities returns vulnerabilities for the given image.
func Scan(opt *Options) (*Result, error) {
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
		if !isInstalled(scanType.String()) {
			log.Warn().Msgf("skipping scan: %s is not installed", scanType)
			continue
		}

		var c *exec.Cmd
		f := config.GetTempFilePath(scanType.String())

		switch scanType {
		case Grype:
			c = makeGrypeCmd(opt.Image, f)
		case Snyk:
			c = makeSnykCmd(opt.Image, f)
		case Trivy:
			c = makeTrivyCmd(opt.Image, f)
		default:
			return nil, errors.Errorf("unsupported scan type: %s", scanType)
		}

		if err := runCmd(c, f); err != nil {
			return nil, errors.Wrap(err, "error running vulnerability scanner command")
		}

		log.Info().Msgf("%s scan complete: %s", scanType, f)

		r.Files[scanType] = f
	}

	return r, nil
}

func runCmd(cmd *exec.Cmd, path string) error {
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()

	if _, e := os.Stat(path); errors.Is(e, os.ErrNotExist) {
		// only err if the file doesn't exist
		// some scanners (snyk) will return 1 when they find vulnerabilities
		log.Error().Err(err).Msgf("out: %s, err: %s", outb.String(), errb.String())
		return errors.Wrapf(err, "error executing scanner command: %s", cmd.String())
	}

	return nil
}

func isInstalled(c string) bool {
	if _, err := exec.LookPath(c); err != nil {
		return false
	}
	return true
}
