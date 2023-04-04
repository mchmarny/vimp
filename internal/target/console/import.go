package console

import (
	"encoding/json"
	"os"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

var (
	SampleURIs = []string{
		"console://stdout",
	}
)

// Import prints the vulnerabilities to stdout.
func Import(uri string, vuls []*data.ImageVulnerability) error {
	if vuls == nil {
		return errors.New("vulnerabilities required")
	}

	var f *os.File
	if uri == "console://stderr" {
		f = os.Stderr
	} else {
		f = os.Stdout
	}

	je := json.NewEncoder(f)
	je.SetIndent("", "  ")
	if err := je.Encode(vuls); err != nil {
		return errors.Wrap(err, "error encoding the output to stdout")
	}

	return nil
}
