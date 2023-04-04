package processor

import (
	"encoding/json"
	"os"

	"github.com/mchmarny/vimp/internal/target"
	"github.com/mchmarny/vimp/pkg/query"
	"github.com/pkg/errors"
)

// Query imports the vulnerability report to the target data store.
func Query(opt *query.Options) error {
	if opt == nil {
		return errors.New("options required")
	}
	if err := opt.Validate(); err != nil {
		return errors.Wrap(err, "error validating options")
	}

	q, err := target.GetQuerier(opt.Target)
	if err != nil {
		return errors.Wrap(err, "error getting importer")
	}

	list, err := q(opt)
	if err != nil {
		return errors.Wrap(err, "error converting source")
	}

	if list == nil {
		return errors.New("expected non-nil result")
	}

	f := os.Stdout
	je := json.NewEncoder(f)
	je.SetIndent("", "  ")
	if err := je.Encode(list); err != nil {
		return errors.Wrap(err, "error encoding the output to stdout")
	}

	return nil
}
