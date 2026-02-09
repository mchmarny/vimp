package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/mchmarny/vimp/pkg/logging"
	"github.com/pkg/errors"
	c "github.com/urfave/cli/v3"
)

const (
	name = "vimp"

	// categoryFunctional groups core CLI commands.
	categoryFunctional = "Functional"
)

var logLevel = slog.LevelInfo

// Execute runs the CLI.
func Execute(version string, args []string) {
	logging.SetDefaultCLILogger(logLevel)

	app, err := newApp(version)
	if err != nil {
		slog.Error("error creating app", "error", err)
		os.Exit(1)
	}

	if err := app.Run(context.Background(), args); err != nil {
		slog.Error("error running app", "error", err)
		os.Exit(1)
	}
}

func newApp(version string) (*c.Command, error) {
	if version == "" {
		return nil, errors.New("version must be set")
	}

	app := &c.Command{
		EnableShellCompletion: true,
		HideHelpCommand:       true,
		Suggest:               true,
		Name:                  name,
		Version:               version,
		Usage: `Aggregate vulnerability scans from multiple container image scanners to
identify discrepancies and get comprehensive exposure analysis.`,
		ConfigureShellCompletionCommand: func(cmd *c.Command) {
			cmd.Hidden = false
			cmd.Category = "Utilities"
			cmd.Usage = "Output shell completion script for bash, zsh, fish, or powershell"
		},
		Flags: []c.Flag{
			&c.BoolFlag{
				Name:  "debug",
				Usage: "verbose output",
				Action: func(_ context.Context, _ *c.Command, debug bool) error {
					if debug {
						logLevel = slog.LevelDebug
						logging.SetDefaultCLILogger(logLevel)
					}
					return nil
				},
			},
		},
		Commands: []*c.Command{
			scanCmd,
			impCmd,
			queryCmd,
			serverCmd,
		},
		ShellComplete: commandLister,
	}

	return app, nil
}

// commandLister outputs available commands for shell completion.
func commandLister(_ context.Context, cmd *c.Command) {
	if cmd == nil || cmd.Root() == nil {
		return
	}
	for _, c := range cmd.Root().Commands {
		if c.Hidden {
			continue
		}
		fmt.Println(c.Name)
	}
}
