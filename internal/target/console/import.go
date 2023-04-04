package console

import (
	"encoding/json"
	"os"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

// Import prints the vulnerabilities to stdout.
func Import(uri string, vuls []*data.ImageVulnerability) error {
	if uri != "console://stdout" {
		return errors.New("target uri must be console://stdout")
	}

	if vuls == nil {
		return errors.New("vulnerabilities required")
	}

	je := json.NewEncoder(os.Stdout)
	je.SetIndent("", "  ")
	if err := je.Encode(vuls); err != nil {
		return errors.Wrap(err, "error encoding the output to stdout")
	}

	return nil
}
