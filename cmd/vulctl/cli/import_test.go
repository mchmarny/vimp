package cli

import (
	"flag"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestImportCmd(t *testing.T) {
	set := flag.NewFlagSet("", flag.ContinueOnError)
	set.String(
		"import",
		"data/grype-json.json",
		"grype",
	)

	c := cli.NewContext(newTestApp(t), set, nil)
	err := importCmd(c)
	assert.NoError(t, err)
}

func newTestApp(t *testing.T) *cli.App {
	app, err := newApp("v0.0.0-test", "test", time.Now().UTC().Format(time.RFC3339))
	assert.NoError(t, err)
	return app
}
