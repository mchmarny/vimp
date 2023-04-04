package cmd

import (
	"os"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	c "github.com/urfave/cli/v2"
)

const (
	name = "vimp"
)

// Execute runs the CLI.
func Execute(version string, args []string) {
	initLogging()
	app, err := newApp(version)
	if err != nil {
		log.Fatal().Err(err).Msg("error creating app")
	}

	if err := app.Run(args); err != nil {
		log.Fatal().Err(err).Msg("error running app")
	}
}

func newApp(version string) (*c.App, error) {
	if version == "" {
		return nil, errors.New("version must be set")
	}

	app := &c.App{
		EnableBashCompletion: true,
		Suggest:              true,
		Name:                 name,
		Version:              version,
		Usage:                "vulnerability tool",
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
		},
		Commands: []*c.Command{
			impCmd,
			queryCmd,
		},
	}

	return app, nil
}

func printVersion(c *c.Context) {
	log.Info().Msgf(c.App.Version)
}

func initLogging() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	out := zerolog.ConsoleWriter{
		Out: os.Stderr,
		PartsExclude: []string{
			zerolog.TimestampFieldName,
		},
	}

	log.Logger = zerolog.New(out)
}
