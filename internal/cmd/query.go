package cmd

import (
	"context"
	"time"

	"github.com/mchmarny/vimp/internal/processor"
	"github.com/mchmarny/vimp/pkg/query"
	"github.com/pkg/errors"
	c "github.com/urfave/cli/v3"
)

const (
	// defaultQueryTimeout is the default timeout for query operations.
	defaultQueryTimeout = 5 * time.Minute
)

var (
	queryCmd = &c.Command{
		Name:     "query",
		Category: categoryFunctional,
		Usage:    "query imported vulnerabilities",
		Action:   runQuery,
		Flags: []c.Flag{
			targetFlag,
			imageFlag,
			digestFlag,
			exposureFlag,
			diffsOnlyFlag,
			formatFlag,
		},
	}
)

func runQuery(ctx context.Context, cmd *c.Command) error {
	opt := &query.Options{
		Target:    cmd.String(targetFlag.Name),
		Image:     cmd.String(imageFlag.Name),
		Digest:    cmd.String(digestFlag.Name),
		Exposure:  cmd.String(exposureFlag.Name),
		DiffsOnly: cmd.Bool(diffsOnlyFlag.Name),
		Format:    query.ParseOutputFormat(cmd.String(formatFlag.Name)),
	}

	ctx, cancel := context.WithTimeout(ctx, defaultQueryTimeout)
	defer cancel()

	if err := processor.QueryWithContext(ctx, opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
