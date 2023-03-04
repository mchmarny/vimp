package cli

import (
	"fmt"
	"strings"

	"github.com/mchmarny/vulctl/pkg/types"
	c "github.com/urfave/cli/v2"
)

var (
	projectIDFlag = &c.StringFlag{
		Name:    "project",
		Aliases: []string{"p"},
		Usage:   "project ID",
	}

	fileFlag = &c.StringFlag{
		Name:    "file",
		Aliases: []string{"f"},
		Usage:   "path to file to import",
	}

	srcFlag = &c.StringFlag{
		Name:    "src",
		Aliases: []string{"s"},
		Usage:   fmt.Sprintf("file source (e.g. %s, etc.)", strings.Join(types.GetSourceFormatNames(), ", ")),
	}
)
