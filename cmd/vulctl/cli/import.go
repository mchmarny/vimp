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
			projectIDFlag,
			fileFlag,
			srcFlag,
		},
	}
)

func importCmd(c *c.Context) error {
	opt := &vul.ImportOptions{
		ProjectID: c.String(projectIDFlag.Name),
		File:      c.String(fileFlag.Name),
		Quiet:     isQuiet(c),
	}

	f, err := types.ParseSourceFormat(c.String(srcFlag.Name))
	if err != nil {
		return errors.Wrap(err, "error parsing source format")
	}
	opt.Format = f

	printVersion(c)

	if err := vul.Import(c.Context, opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
