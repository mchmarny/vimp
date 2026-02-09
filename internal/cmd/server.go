package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"time"

	"github.com/mchmarny/vimp/internal/config"
	"github.com/mchmarny/vimp/internal/server"
	"github.com/pkg/errors"
	c "github.com/urfave/cli/v3"
)

var (
	serverCmd = &c.Command{
		Name:     "server",
		Category: categoryFunctional,
		Usage:    "start local HTTP server for vulnerability dashboard",
		Description: `Start a local HTTP server to view vulnerability data in a web dashboard.

The dashboard provides:
  - Overview statistics (images, exposures, severity distribution)
  - Registry breakdown
  - Recent scan results
  - Image detail with time series charts
  - Searchable image list

Examples:
  vimp server
  vimp server --port 3000
  vimp server --target sqlite:///path/to/db.db
  vimp server --open`,
		Action: runServer,
		Flags: []c.Flag{
			portFlag,
			targetFlag,
			openFlag,
		},
	}
)

func runServer(ctx context.Context, cmd *c.Command) error {
	port := cmd.Int(portFlag.Name)
	target := cmd.String(targetFlag.Name)
	openBrowser := cmd.Bool(openFlag.Name)

	// Use default database if not specified
	if target == "" {
		target = config.GetDefaultDBPath()
	}

	// Get version from app
	version := cmd.Root().Version

	slog.Info("starting server",
		"port", port,
		"target", target,
		"version", version,
	)

	cfg := &server.Config{
		Port:    port,
		Target:  target,
		Version: version,
	}

	srv, err := server.New(cfg)
	if err != nil {
		return errors.Wrap(err, "failed to create server")
	}
	defer srv.Close()

	// Open browser if requested
	if openBrowser {
		go openInBrowser(ctx, port)
	}

	return srv.Start(ctx)
}

// openInBrowser opens the dashboard URL in the default browser.
func openInBrowser(ctx context.Context, port int) {
	// Wait for server to be ready
	time.Sleep(500 * time.Millisecond)

	url := fmt.Sprintf("http://localhost:%d", port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", url)
	case "linux":
		cmd = exec.CommandContext(ctx, "xdg-open", url)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url)
	default:
		slog.Info("open browser manually", "url", url)
		return
	}

	if err := cmd.Run(); err != nil {
		slog.Warn("failed to open browser", "url", url, "error", err)
	}
}
