package processor

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"

	"github.com/mchmarny/vimp/internal/target"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/mchmarny/vimp/pkg/query"
	"github.com/mchmarny/vimp/pkg/sarif"
	"github.com/pkg/errors"
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
		slog.Info("querying (undefined)", "target", opt.Target)
	case query.Images:
		slog.Info("querying", "target", opt.Target)
	case query.Digests:
		slog.Info("querying", "target", opt.Target, "image", opt.Image)
	case query.Exposure:
		slog.Info("querying", "target", opt.Target, "image", opt.Image, "digest", opt.Digest)
	case query.Packages:
		slog.Info("querying", "target", opt.Target, "image", opt.Image, "digest", opt.Digest)
	case query.TimeSeries:
		slog.Info("querying time-series", "target", opt.Target, "image", opt.Image)
	case query.CommonVulns:
		slog.Info("querying common vulnerabilities", "target", opt.Target, "images", len(opt.Images))
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

	// Handle SARIF output format
	if opt.Format == query.FormatSARIF {
		switch v := list.(type) {
		case []*data.ImageVulnerability:
			list = sarif.FromVulnerabilities(v, "vimp", "1.0.0")
		case *query.ImageExposureResult:
			list = sarif.FromExposureResult(v, "vimp", "1.0.0")
		default:
			return errors.New("SARIF output is only supported for vulnerability queries (use --image and --digest)")
		}
	}

	f := os.Stdout
	je := json.NewEncoder(f)
	je.SetIndent("", "  ")
	if err := je.Encode(list); err != nil {
		return errors.Wrap(err, "error encoding the output to stdout")
	}

	return nil
}
