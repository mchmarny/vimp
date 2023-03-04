package cli

import (
	"fmt"
	"strings"

	"github.com/mchmarny/vulctl/pkg/types"
	c "github.com/urfave/cli/v2"
)

var (
	uriFlag = &c.StringFlag{
		Name:    "image",
		Aliases: []string{"i"},
		Usage:   "image URI (e.g. us-docker.pkg.dev/project/repo/img@sha256:f6efe...)",
	}

	fileFlag = &c.StringFlag{
		Name:    "file",
		Aliases: []string{"f"},
		Usage:   "path to file to import",
	}

	srcFlag = &c.StringFlag{
		Name:    "source",
		Aliases: []string{"s"},
		Usage:   fmt.Sprintf("file source (e.g. %s, etc.)", strings.Join(types.GetSourceFormatNames(), ", ")),
	}
)
