package cmd

import (
	"fmt"
	"strings"

	"github.com/mchmarny/vimp/internal/scanner"
	"github.com/mchmarny/vimp/internal/target"
	c "github.com/urfave/cli/v3"
)

var (
	sourceFlag = &c.StringFlag{
		Name:     "source",
		Aliases:  []string{"s"},
		Usage:    "uri of the image from which the report was generated (e.g. ghcr.io/repo/img@sha256:f6efe...)",
		Required: true,
	}

	fileFlag = &c.StringFlag{
		Name:    "file",
		Aliases: []string{"f"},
		Usage:   "path to vulnerability report to import, image scans will automatically be performed if not provided",
	}

	scannersFlag = &c.StringFlag{
		Name:  "scanners",
		Usage: fmt.Sprintf("comma separated list of scanners to use (e.g. %s, etc.), ignored if file is provided", strings.Join(scanner.GetSampleScanners(), ", ")),
	}

	targetFlag = &c.StringFlag{
		Name:    "target",
		Aliases: []string{"t"},
		Sources: c.EnvVars("VIMP_TARGET"),
		Usage:   fmt.Sprintf("target (e.g. %s, etc.)", strings.Join(target.GetSampleTargets(), ", ")),
	}

	imageFlag = &c.StringFlag{
		Name:    "image",
		Aliases: []string{"img"},
		Usage:   "image uri without the tag or digest (e.g. ghcr.io/repo/img)",
	}

	digestFlag = &c.StringFlag{
		Name:    "digest",
		Aliases: []string{"dig"},
		Usage:   "sha:256 digest of the image (e.g. sha256:f6efe...)",
	}

	exposureFlag = &c.StringFlag{
		Name:  "exposure",
		Usage: "ID of the exposure to query (e.g. CVE-2021-1234)",
	}

	diffsOnlyFlag = &c.BoolFlag{
		Name:  "diff",
		Usage: "only return differences between sources",
	}

	formatFlag = &c.StringFlag{
		Name:  "format",
		Usage: "output format (json, sarif)",
		Value: "json",
	}

	// Scan command flags
	scanImageFlag = &c.StringFlag{
		Name:     "image",
		Aliases:  []string{"i"},
		Usage:    "container image to scan (e.g. alpine:latest, ghcr.io/repo/img@sha256:...)",
		Required: true,
	}

	scannerFlag = &c.StringSliceFlag{
		Name:    "scanner",
		Aliases: []string{"s"},
		Usage:   fmt.Sprintf("scanner to use (can be repeated, supported: %s)", strings.Join(scanner.GetAllScannerNames(), ", ")),
	}

	outputDirFlag = &c.StringFlag{
		Name:    "output",
		Aliases: []string{"o"},
		Usage:   "output directory for scan reports",
		Value:   "./reports",
	}

	yesFlag = &c.BoolFlag{
		Name:    "yes",
		Aliases: []string{"y"},
		Usage:   "skip confirmation prompt (auto-yes)",
	}

	scanOnlyFlag = &c.BoolFlag{
		Name:  "scan-only",
		Usage: "skip auto-import after scanning (only save JSON reports)",
	}

	discoFlag = &c.BoolFlag{
		Name:  "disco",
		Usage: "discover recent tags from registry (ignores tag in image URI)",
	}

	tagsFlag = &c.IntFlag{
		Name:  "tags",
		Usage: "number of tags to discover (requires --disco)",
		Value: 5,
	}
)
