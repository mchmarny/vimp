package cli

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	c "github.com/urfave/cli/v2"
)

const (
	name           = "vulctl"
	metaKeyVersion = "version"
	metaKeyCommit  = "commit"
	metaKeyDate    = "date"
)

func Execute(version, commit, date string, args []string) error {
	app, err := newApp(version, commit, date)
	if err != nil {
		return err
	}

	if err := app.Run(args); err != nil {
		return errors.Wrap(err, "error running app")
	}
	return nil
}

func newApp(version, commit, date string) (*c.App, error) {
	if version == "" || commit == "" || date == "" {
		return nil, errors.New("version, commit, and date must be set")
	}

	compileTime, err := time.Parse("2006-01-02T15:04:05Z", date)
	if err != nil {
		log.Debug().Msg("compile time not set, using current")
		compileTime = time.Now()
	}
	dateStr := compileTime.UTC().Format("2006-01-02 15:04 UTC")

	app := &c.App{
		EnableBashCompletion: true,
		Suggest:              true,
		Name:                 name,
		Version:              fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, dateStr),
		Usage:                `vulnerability management tool`,
		Compiled:             compileTime,
		Flags: []c.Flag{
			&c.BoolFlag{
				Name:  "debug",
				Usage: "verbose output",
				Action: func(c *c.Context, debug bool) error {
					if debug {
						zerolog.SetGlobalLevel(zerolog.DebugLevel)
					}
					return nil
				},
			},
			&c.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "suppress output unless error",
				Action: func(c *c.Context, quiet bool) error {
					if quiet {
						c.App.Metadata["quiet"] = true
					}
					return nil
				},
			},
		},
		Metadata: map[string]interface{}{
			metaKeyVersion: version,
			metaKeyCommit:  commit,
			metaKeyDate:    date,
		},
		Commands: []*c.Command{
			impCmd,
		},
	}

	return app, nil
}

func isQuiet(c *c.Context) bool {
	_, ok := c.App.Metadata["quiet"]
	if ok {
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	}

	return ok
}

func printVersion(c *c.Context) {
	log.Info().Msgf(c.App.Version)
}
