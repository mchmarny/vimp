package postgres

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
	"github.com/mchmarny/vimp/pkg/query"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var (
	querySummary = `SELECT 
						image, 
						digest, 
						COUNT(*) exposures, 
						COUNT(DISTINCT source) sources, 
						COUNT(DISTINCT package) packages, 
						MAX(score) max_score, 
						MIN(processed) first_processed, 
						MAX(processed) last_processed 
					  FROM vulns 
					  WHERE image = COALESCE($1, image) 
					  GROUP BY image, digest 
				`

	queryExposures = `SELECT
						exposure,
						source,
						severity,
						score,
						MAX(processed) last_processed
					FROM vulns
					WHERE image = $1
					AND digest = $2
					GROUP BY exposure, source, severity, score
					ORDER BY 1, 2, 3 DESC, 4 DESC
				`
	queryPackages = `SELECT
						source,
						package,
						version,
						severity,
						score,
						MAX(processed) last_processed
					FROM vulns
					WHERE image = $1
					AND digest = $2
					AND exposure = $3
					GROUP BY source, package, version, severity, score
					ORDER BY 1, 2, 3, 4, 5 DESC
`
)

// Query returns all rows from the table.
func Query(opt *query.Options) (any, error) {
	if opt == nil {
		return nil, errors.New("options are required")
	}

	ctx := context.Background()
	db, err := getDB(ctx, opt.Target)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get store")
	}

	var q string
	var a []interface{}
	qt, err := opt.GetQuery()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get query type")
	}

	switch qt {
	case query.Images:
		q = querySummary
		a = []any{nil}
	case query.Digests:
		q = querySummary
		a = []any{opt.Image}
	case query.Exposure:
		q = queryExposures
		a = []any{opt.Image, opt.Digest}
	case query.Packages:
		q = queryPackages
		a = []any{opt.Image, opt.Digest, opt.Exposure}
	default:
		return nil, errors.Errorf("unsupported query type: %v", qt)
	}

	rows, err := db.Query(ctx, q, a...)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Debug().
			Err(err).
			Str("query", q).
			Interface("args", a).
			Msg("error executing query")
		return nil, errors.Wrapf(err, "failed to execute select statement")
	}
	defer rows.Close()

	switch qt {
	case query.Images:
		return scanSummary(rows)
	case query.Digests:
		return scanSummary(rows)
	case query.Exposure:
		return scanExposure(opt, rows)
	case query.Packages:
		return scanPackages(opt, rows)
	}

	return nil, errors.Errorf("unsupported query type: %v", qt)
}

// scanSummary scans the rows and returns a map of image to digest to summary.
// works for both all and single image queries.
func scanSummary(rows pgx.Rows) (any, error) {
	r := make(map[string]*query.ImageResult, 0)

	for rows.Next() {
		var image string
		var digest string
		q := &query.DigestSummaryResult{}

		if err := rows.Scan(&image, &digest,
			&q.Exposures, &q.Sources, &q.Packages, &q.HighScore, &q.First, &q.Last); err != nil {
			return nil, errors.Wrapf(err, "failed to scan image row")
		}

		if _, ok := r[image]; !ok {
			r[image] = &query.ImageResult{
				Versions: make(map[string]*query.DigestSummaryResult, 0),
			}
		}

		r[image].Versions[digest] = q
	}

	log.Info().Msgf("found %d records", len(r))

	return r, nil
}

func scanExposure(opt *query.Options, rows pgx.Rows) (any, error) {
	list := make(map[string][]*query.ExposureResult, 0)

	for rows.Next() {
		var exposure string
		e := &query.ExposureResult{}

		if err := rows.Scan(&exposure, &e.Source, &e.Severity, &e.Score, &e.Last); err != nil {
			return nil, errors.Wrapf(err, "failed to scan exposure row")
		}

		list[exposure] = append(list[exposure], e)
	}

	r := &query.ImageExposureResult{
		Image:     opt.Image,
		Digest:    opt.Digest,
		Exposures: list,
	}

	// if all (not just diffs) are requested, return the full list
	if !opt.DiffsOnly {
		return r, nil
	}

	u := make(map[string][]*query.ExposureResult, 0)

	for k, v := range list {
		if query.HasUniqueExposureSeverityScore(v) {
			u[k] = v
		}
	}

	// update the list with the unique exposures
	r.Exposures = u

	return r, nil
}

func scanPackages(opt *query.Options, rows pgx.Rows) (any, error) {
	r := &query.PackageExposureResult{
		Image:    opt.Image,
		Digest:   opt.Digest,
		Exposure: opt.Exposure,
		Packages: make([]*query.PackageResult, 0),
	}

	for rows.Next() {
		q := &query.PackageResult{}

		if err := rows.Scan(&q.Source, &q.Package, &q.Version, &q.Severity, &q.Score, &q.Last); err != nil {
			return nil, errors.Wrapf(err, "failed to scan package row")
		}

		r.Packages = append(r.Packages, q)
	}

	log.Info().Msgf("found %d records", len(r.Packages))

	return r, nil
}
