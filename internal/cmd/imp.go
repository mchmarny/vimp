package cmd

import (
	"context"
	"time"

	"github.com/mchmarny/vimp/internal/processor"
	"github.com/pkg/errors"
	c "github.com/urfave/cli/v3"
)

const (
	// defaultImportTimeout is the default timeout for import operations.
	defaultImportTimeout = 10 * time.Minute
)

var (
	impCmd = &c.Command{
		Name:     "import",
		Category: categoryFunctional,
		Usage:    "import vulnerabilities from file",
		Action:   runImport,
		Flags: []c.Flag{
			sourceFlag,
			fileFlag,
			targetFlag,
			scannersFlag,
		},
	}
)

func runImport(ctx context.Context, cmd *c.Command) error {
	opt := &processor.ImportOptions{
		Source:   cmd.String(sourceFlag.Name),
		File:     cmd.String(fileFlag.Name),
		Target:   cmd.String(targetFlag.Name),
		Scanners: cmd.String(scannersFlag.Name),
	}

	ctx, cancel := context.WithTimeout(ctx, defaultImportTimeout)
	defer cancel()

	if err := processor.ImportWithContext(ctx, opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
