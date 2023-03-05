package cli

import (
	"fmt"
	"strings"

	"github.com/mchmarny/vulctl/pkg/types"
	c "github.com/urfave/cli/v2"
)

var (
	projectFlag = &c.StringFlag{
		Name:    "project",
		Aliases: []string{"p"},
		Usage:   "GCP project ID where the vulnerabilities will be imported",
	}

	sourceFlag = &c.StringFlag{
		Name:    "source",
		Aliases: []string{"s"},
		Usage:   "uri of the image from which the report was generated (e.g. us-docker.pkg.dev/project/repo/img@sha256:f6efe...)",
	}

	fileFlag = &c.StringFlag{
		Name:    "file",
		Aliases: []string{"f"},
		Usage:   "path to vulnerability report to import",
	}

	formatFlag = &c.StringFlag{
		Name:    "format",
		Aliases: []string{"t"},
		Usage:   fmt.Sprintf("file type (e.g. %s, etc.)", strings.Join(types.GetSourceFormatNames(), ", ")),
	}
)
