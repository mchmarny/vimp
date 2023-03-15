package cli

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestImport(t *testing.T) {
	// test no arg import
	set := flag.NewFlagSet("", flag.ContinueOnError)
	c := cli.NewContext(newTestApp(t), set, nil)
	err := importCmd(c)
	assert.Error(t, err)

	// test all formats
	for _, f := range types.GetSourceFormatNames() {
		set = flag.NewFlagSet("", flag.ContinueOnError)
		set.String(projectFlag.Name, types.TestProjectID, "")
		set.String(sourceFlag.Name, "us-docker.pkg.dev/project/repo/img@sha256:f6efe...", "")
		set.String(fileFlag.Name, fmt.Sprintf("../../../examples/data/%s.json", f), "")
		set.String(formatFlag.Name, f, "")

		c = cli.NewContext(newTestApp(t), set, nil)
		err = importCmd(c)
		assert.NoError(t, err)
	}
}

func newTestApp(t *testing.T) *cli.App {
	app, err := newApp("v0.0.0-test", "test", time.Now().UTC().Format(time.RFC3339))
	assert.NoError(t, err)
	return app
}
