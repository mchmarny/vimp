package cmd

import (
	"fmt"
	"strings"

	"github.com/mchmarny/vimp/internal/target"
	c "github.com/urfave/cli/v2"
)

var (
	sourceFlag = &c.StringFlag{
		Name:    "source",
		Aliases: []string{"s"},
		Usage:   "uri of the image from which the report was generated (e.g. ghcr.io/repo/img@sha256:f6efe...)",
	}

	fileFlag = &c.StringFlag{
		Name:    "file",
		Aliases: []string{"f"},
		Usage:   "path to vulnerability report to import",
	}

	targetFlag = &c.StringFlag{
		Name:    "target",
		Aliases: []string{"t"},
		Usage:   fmt.Sprintf("target (e.g. %s, etc.)", strings.Join(target.GetSampleTargets(), ", ")),
	}
)
