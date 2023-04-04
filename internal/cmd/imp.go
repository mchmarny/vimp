package cmd

import (
	"github.com/mchmarny/vimp/internal/processor"
	"github.com/pkg/errors"
	c "github.com/urfave/cli/v2"
)

var (
	impCmd = &c.Command{
		Name:   "import",
		Usage:  "import vulnerabilities from file",
		Action: runImport,
		Flags: []c.Flag{
			sourceFlag,
			fileFlag,
			targetFlag,
		},
	}
)

func runImport(c *c.Context) error {
	opt := &processor.ImportOptions{
		Source: c.String(sourceFlag.Name),
		File:   c.String(fileFlag.Name),
		Target: c.String(targetFlag.Name),
	}

	printVersion(c)

	if err := processor.Import(opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
