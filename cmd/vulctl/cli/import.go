package cli

import (
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/mchmarny/vulctl/pkg/vul"
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
			projectFlag,
			sourceFlag,
			fileFlag,
			formatFlag,
		},
	}
)

func importCmd(c *c.Context) error {
	f, err := types.ParseSourceFormat(c.String(formatFlag.Name))
	if err != nil {
		return errors.Wrap(err, "error parsing source format")
	}

	opt := &types.ImportOptions{
		Project: c.String(projectFlag.Name),
		Source:  c.String(sourceFlag.Name),
		File:    c.String(fileFlag.Name),
		Format:  f,
		Quiet:   isQuiet(c),
	}

	printVersion(c)

	if err := vul.Import(c.Context, opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
