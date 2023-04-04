package sqlite

import (
	"time"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

const (
	insertSQL = `INSERT INTO vul 
		(image, digest, source, processed, cve, package, version, severity, score, fixed) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
		ON CONFLICT(image,digest,source) 
		DO UPDATE SET
			processed=excluded.processed,
			cve=excluded.cve,
			package=excluded.package,
			version=excluded.version,
			severity=excluded.severity,
			score=excluded.score,
			fixed=excluded.fixed
		WHERE image=excluded.image
		AND digest=excluded.digest
		AND source=excluded.source
  `
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
			v.CVE,
			v.Package,
			v.Version,
			v.Severity,
			v.Score,
			v.IsFixed,
		)
		if err != nil {
			if err = tx.Rollback(); err != nil {
				return errors.Wrapf(err, "failed to rollback transaction")
			}
			return errors.Wrapf(err, "failed to execute batch statement")
		}
	}

	if err = tx.Commit(); err != nil {
		return errors.Wrapf(err, "failed to commit transaction")
	}

	return nil
}
