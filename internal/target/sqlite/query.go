package sqlite

import (
	"database/sql"

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
					  FROM vul 
					  WHERE image = COALESCE(?, image)
					  GROUP BY image, digest
					  `

	queryExposures = `SELECT
						exposure,
						source,
						severity,
						score,
						MAX(processed) last_processed
					FROM vul
					WHERE image = ?
					AND digest = ?
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
					FROM vul
					WHERE image = ?
					AND digest = ?
					AND exposure = ?
					GROUP BY source, package, version, severity, score
					ORDER BY 1, 2, 3, 4, 5 DESC
`
)

// Query returns all rows from the table.
func Query(opt *query.Options) (any, error) {
	if opt == nil {
		return nil, errors.New("options are required")
	}

	db, err := getStore(opt.Target)
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

	stmt, err := db.Prepare(q)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to prepare select statement")
	}

	rows, err := stmt.Query(a...)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
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
func scanSummary(rows *sql.Rows) (any, error) {
	r := make(map[string]*query.ImageResult, 0)

	for rows.Next() {
		var image string
		var digest string
		var exposures int
		var sources int
		var packages int
		var maxScore float32
		var firstProcessed string
		var lastProcessed string

		if err := rows.Scan(&image, &digest, &exposures, &sources, &packages,
			&maxScore, &firstProcessed, &lastProcessed); err != nil {
			return nil, errors.Wrapf(err, "failed to scan image row")
		}

		if _, ok := r[image]; !ok {
			r[image] = &query.ImageResult{
				Versions: make(map[string]*query.DigestSummaryResult, 0),
			}
		}

		r[image].Versions[digest] = &query.DigestSummaryResult{
			Exposures: exposures,
			Sources:   sources,
			Packages:  packages,
			HighScore: maxScore,
			First:     parseTime(firstProcessed),
			Last:      parseTime(lastProcessed),
		}
	}

	log.Info().Msgf("found %d records", len(r))

	return r, nil
}

func scanExposure(opt *query.Options, rows *sql.Rows) (any, error) {
	list := make(map[string][]*query.ExposureResult, 0)

	for rows.Next() {
		var exposure string
		var source string
		var severity string
		var score float32
		var lastProcessed string

		if err := rows.Scan(&exposure, &source, &severity, &score, &lastProcessed); err != nil {
			return nil, errors.Wrapf(err, "failed to scan exposure row")
		}

		e := &query.ExposureResult{
			Source:   source,
			Severity: severity,
			Score:    score,
			Last:     parseTime(lastProcessed),
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
		if !query.HasUniqueExposures(v) {
			u[k] = v
		}
	}

	// update the list with the unique exposures
	r.Exposures = u

	return r, nil
}

func scanPackages(opt *query.Options, rows *sql.Rows) (any, error) {
	r := &query.PackageExposureResult{
		Image:    opt.Image,
		Digest:   opt.Digest,
		Exposure: opt.Exposure,
		Packages: make([]*query.PackageResult, 0),
	}

	for rows.Next() {
		var source string
		var pkg string
		var version string
		var severity string
		var score float32
		var lastProcessed string

		if err := rows.Scan(&source, &pkg, &version, &severity, &score, &lastProcessed); err != nil {
			return nil, errors.Wrapf(err, "failed to scan package row")
		}

		r.Packages = append(r.Packages, &query.PackageResult{
			Source:   source,
			Package:  pkg,
			Version:  version,
			Severity: severity,
			Score:    score,
			Last:     parseTime(lastProcessed),
		})
	}

	log.Info().Msgf("found %d records", len(r.Packages))

	return r, nil
}
