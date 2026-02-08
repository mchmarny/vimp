package processor

import (
	"context"
	"encoding/json"
	"os"

	"github.com/mchmarny/vimp/internal/target"
	"github.com/mchmarny/vimp/pkg/query"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Query queries the vulnerability data from the target data store.
func Query(opt *query.Options) error {
	return QueryWithContext(context.Background(), opt)
}

// QueryWithContext queries the vulnerability data with context support.
func QueryWithContext(ctx context.Context, opt *query.Options) error {
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
	case query.Undefined:
		log.Info().
			Str("target", opt.Target).
			Msg("querying (undefined):")
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
	case query.TimeSeries:
		log.Info().
			Str("target", opt.Target).
			Str("image", opt.Image).
			Msg("querying time-series:")
	case query.CommonVulns:
		log.Info().
			Str("target", opt.Target).
			Int("images", len(opt.Images)).
			Msg("querying common vulnerabilities:")
	}

	q, err := target.GetQuerier(opt.Target)
	if err != nil {
		return errors.Wrap(err, "error getting querier")
	}

	list, err := q(ctx, opt)
	if err != nil {
		return errors.Wrap(err, "error querying data")
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
