package sqlite

import (
	"strings"
	"time"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	insertSQL = `INSERT INTO vul 
		(image, digest, source, processed, exposure, package, version, severity, score, fixed) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
		ON CONFLICT(image, digest, source, exposure, package, version) 
		DO UPDATE SET
			processed=excluded.processed,
			exposure=excluded.exposure,
			package=excluded.package,
			version=excluded.version,
			severity=excluded.severity,
			score=excluded.score,
			fixed=excluded.fixed
		WHERE image=excluded.image
		AND digest=excluded.digest
		AND source=excluded.source
		AND exposure=excluded.exposure
		AND package=excluded.package
		AND version=excluded.version
  `
)

var (
	SampleURIs = []string{
		"sqlite://data.db",
	}
)

func Import(uri string, vuls []*data.ImageVulnerability) error {
	db, err := getStore(uri)
	if err != nil {
		return errors.Wrapf(err, "failed to get store")
	}
	defer db.Close()

	stmt, err := db.Prepare(insertSQL)
	if err != nil {
		return errors.Wrapf(err, "failed to prepare batch import statement")
	}

	tx, err := db.Begin()
	if err != nil {
		return errors.Wrapf(err, "failed to begin transaction")
	}

	for _, v := range vuls {
		_, err = tx.Stmt(stmt).Exec(
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
			if err = tx.Rollback(); err != nil {
				return errors.Wrapf(err, "failed to rollback transaction")
			}
			return errors.Wrapf(err, "failed to execute batch statement")
		}
	}

	if err = tx.Commit(); err != nil {
		return errors.Wrapf(err, "failed to commit transaction")
	}

	log.Debug().Int("count", len(vuls)).Msg("inserted")

	return nil
}
