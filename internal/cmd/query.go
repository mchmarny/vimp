package cmd

import (
	"context"
	"time"

	"github.com/mchmarny/vimp/internal/processor"
	"github.com/mchmarny/vimp/pkg/query"
	"github.com/pkg/errors"
	c "github.com/urfave/cli/v2"
)

const (
	// defaultQueryTimeout is the default timeout for query operations.
	defaultQueryTimeout = 5 * time.Minute
)

var (
	queryCmd = &c.Command{
		Name:   "query",
		Usage:  "query imported vulnerabilities",
		Action: runQuery,
		Flags: []c.Flag{
			targetFlag,
			imageFlag,
			digestFlag,
			exposureFlag,
			diffsOnlyFlag,
		},
	}
)

func runQuery(cc *c.Context) error {
	opt := &query.Options{
		Target:    cc.String(targetFlag.Name),
		Image:     cc.String(imageFlag.Name),
		Digest:    cc.String(digestFlag.Name),
		Exposure:  cc.String(exposureFlag.Name),
		DiffsOnly: cc.Bool(diffsOnlyFlag.Name),
	}

	printVersion(cc)

	ctx, cancel := context.WithTimeout(cc.Context, defaultQueryTimeout)
	defer cancel()

	if err := processor.QueryWithContext(ctx, opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
