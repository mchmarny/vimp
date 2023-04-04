package cmd

import (
	"github.com/mchmarny/vimp/internal/processor"
	"github.com/mchmarny/vimp/pkg/query"
	"github.com/pkg/errors"
	c "github.com/urfave/cli/v2"
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
			cveFlag,
			diffsOnlyFlag,
		},
	}
)

func runQuery(c *c.Context) error {
	opt := &query.Options{
		Target:    c.String(targetFlag.Name),
		Image:     c.String(imageFlag.Name),
		Digest:    c.String(digestFlag.Name),
		CVE:       c.String(cveFlag.Name),
		DiffsOnly: c.Bool(diffsOnlyFlag.Name),
	}

	printVersion(c)

	if err := processor.Query(opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
