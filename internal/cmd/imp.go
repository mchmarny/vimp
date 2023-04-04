package cmd

import (
	"github.com/mchmarny/vimp/internal/processor"
	"github.com/pkg/errors"
	c "github.com/urfave/cli/v2"
)

var (
	impCmd = &c.Command{
		Name:    "import",
		Aliases: []string{"imp"},
		Usage:   "import vulnerabilities from file",
		Action:  importCmd,
		Flags: []c.Flag{
			sourceFlag,
			fileFlag,
			targetFlag,
		},
	}
)

func importCmd(c *c.Context) error {
	opt := &processor.Options{
		Source: c.String(sourceFlag.Name),
		File:   c.String(fileFlag.Name),
		Target: c.String(targetFlag.Name),
	}

	printVersion(c)

	if err := processor.Process(opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
