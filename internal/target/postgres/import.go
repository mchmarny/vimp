package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	insertSQL = `INSERT INTO vul (image, digest, source, processed, exposure, package, version, severity, score, fixed)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (image, digest, source, exposure, package, version)
		DO UPDATE SET
			processed = EXCLUDED.processed,
			severity = EXCLUDED.severity,
			score = EXCLUDED.score,
			fixed = EXCLUDED.fixed
  `
)

func Import(ctx context.Context, uri string, vuls []*data.ImageVulnerability) error {
	db, err := getDB(ctx, uri)
	if err != nil {
		return errors.Wrapf(err, "failed to get store")
	}
	defer db.Close(ctx)

	tx, err := db.Begin(ctx)
	if err != nil {
		return errors.Wrapf(err, "failed to begin transaction")
	}

	for _, v := range vuls {
		select {
		case <-ctx.Done():
			_ = tx.Rollback(ctx)
			return ctx.Err()
		default:
		}

		_, err = tx.Exec(ctx, insertSQL,
			v.Image,
			v.Digest,
			v.Source,
			v.ProcessedAt.Format(time.RFC3339),
			strings.ToUpper(v.Exposure),
			v.Package,
			v.Version,
			v.Severity,
			v.Score,
			v.IsFixed,
		)
		if err != nil {
			log.Err(err).Msgf("insert: %s", insertSQL)
			if err = tx.Rollback(ctx); err != nil {
				return errors.Wrapf(err, "failed to rollback transaction")
			}
			return errors.Wrapf(err, "failed to execute batch statement")
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return errors.Wrapf(err, "failed to commit transaction")
	}

	log.Debug().Int("count", len(vuls)).Msg("inserted")

	return nil
}
