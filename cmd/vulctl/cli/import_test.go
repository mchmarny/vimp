package cli

import (
	"flag"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestImport(t *testing.T) {
	set := flag.NewFlagSet("", flag.ContinueOnError)
	c := cli.NewContext(newTestApp(t), set, nil)
	err := importCmd(c)
	assert.Error(t, err)

	set.String(sourceFlag.Name, "us-docker.pkg.dev/project/repo/img@sha256:f6efe...", "")
	set.String(fileFlag.Name, "../../../data/grype.json", "")
	set.String(formatFlag.Name, "grype", "")

	c = cli.NewContext(newTestApp(t), set, nil)
	err = importCmd(c)
	assert.NoError(t, err)
}

func newTestApp(t *testing.T) *cli.App {
	app, err := newApp("v0.0.0-test", "test", time.Now().UTC().Format(time.RFC3339))
	assert.NoError(t, err)
	return app
}
