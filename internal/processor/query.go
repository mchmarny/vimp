package processor

import (
	"encoding/json"
	"os"

	"github.com/mchmarny/vimp/internal/target"
	"github.com/mchmarny/vimp/pkg/query"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Query imports the vulnerability report to the target data store.
func Query(opt *query.Options) error {
	if opt == nil {
		return errors.New("options required")
	}
	if err := opt.Validate(); err != nil {
		return errors.Wrap(err, "error validating options")
	}

	gt, err := opt.GetQuery()
	if err != nil {
		return errors.Wrap(err, "error parsing query")
	}

	switch gt {
	case query.Images:
		log.Info().
			Str("target", opt.Target).
			Msg("querying:")
	case query.Digests:
		log.Info().
			Str("target", opt.Target).
			Str("image", opt.Image).
			Msg("querying:")
	case query.Exposure:
		log.Info().Str("target", opt.Target).
			Str("image", opt.Image).
			Str("digest", opt.Digest).
			Msg("querying:")
	case query.Packages:
		log.Info().
			Str("target", opt.Target).
			Str("image", opt.Image).
			Str("digest", opt.Digest).
			Msg("querying:")
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
