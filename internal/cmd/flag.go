package cmd

import (
	"fmt"
	"strings"

	"github.com/mchmarny/vimp/internal/target"
	c "github.com/urfave/cli/v2"
)

var (
	sourceFlag = &c.StringFlag{
		Name:     "source",
		Aliases:  []string{"s"},
		Usage:    "uri of the image from which the report was generated (e.g. ghcr.io/repo/img@sha256:f6efe...)",
		Required: true,
	}

	fileFlag = &c.StringFlag{
		Name:     "file",
		Aliases:  []string{"f"},
		Usage:    "path to vulnerability report to import",
		Required: true,
	}

	targetFlag = &c.StringFlag{
		Name:     "target",
		Aliases:  []string{"t"},
		Usage:    fmt.Sprintf("target (e.g. %s, etc.)", strings.Join(target.GetSampleTargets(), ", ")),
		Required: true,
	}

	imageFlag = &c.StringFlag{
		Name:     "image",
		Aliases:  []string{"img"},
		Usage:    "image uri without the tag or digest (e.g. ghcr.io/repo/img)",
		Required: true,
	}

	digestFlag = &c.StringFlag{
		Name:    "digest",
		Aliases: []string{"dig"},
		Usage:   "sha:256 digest of the image (e.g. sha256:f6efe...)",
	}

	cveFlag = &c.StringFlag{
		Name:  "cve",
		Usage: "ID of the CVE to query (e.g. CVE-2021-1234)",
	}

	diffsOnlyFlag = &c.BoolFlag{
		Name:  "diffs-only",
		Usage: "only return differences between sources",
	}
)
