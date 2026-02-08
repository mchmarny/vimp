package cmd

import (
	"context"
	"time"

	"github.com/mchmarny/vimp/internal/processor"
	"github.com/pkg/errors"
	c "github.com/urfave/cli/v2"
)

const (
	// defaultImportTimeout is the default timeout for import operations.
	defaultImportTimeout = 10 * time.Minute
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
			scannersFlag,
		},
	}
)

func runImport(cc *c.Context) error {
	opt := &processor.ImportOptions{
		Source:   cc.String(sourceFlag.Name),
		File:     cc.String(fileFlag.Name),
		Target:   cc.String(targetFlag.Name),
		Scanners: cc.String(scannersFlag.Name),
	}

	printVersion(cc)

	ctx, cancel := context.WithTimeout(cc.Context, defaultImportTimeout)
	defer cancel()

	if err := processor.ImportWithContext(ctx, opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
