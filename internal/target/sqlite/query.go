package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	"github.com/mchmarny/vimp/pkg/query"
	"github.com/pkg/errors"
)

var (
	// querySummary returns image/digest summary. Uses LIKE to match base image with any tag.
	// The pattern "image = ? OR image LIKE ? || ':%'" matches both exact and tagged versions.
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
					  WHERE (? IS NULL OR image = ? OR image LIKE ? || ':%')
					  GROUP BY image, digest
					  `

	// queryExposures returns exposures for an image/digest. Uses LIKE to match base image.
	queryExposures = `SELECT
						exposure,
						source,
						severity,
						score,
						MAX(processed) last_processed
					FROM vul
					WHERE (image = ? OR image LIKE ? || ':%')
					AND digest = ?
					GROUP BY exposure, source, severity, score
					ORDER BY 1, 2, 3 DESC, 4 DESC
				`

	// queryPackages returns packages for an exposure. Uses LIKE to match base image.
	queryPackages = `SELECT
						source,
						package,
						version,
						severity,
						score,
						MAX(processed) last_processed
					FROM vul
					WHERE (image = ? OR image LIKE ? || ':%')
					AND digest = ?
					AND exposure = ?
					GROUP BY source, package, version, severity, score
					ORDER BY 1, 2, 3, 4, 5 DESC
`

	// queryTimeSeries returns vulnerability counts over time. Uses LIKE to match base image.
	queryTimeSeries = `SELECT
						date(processed) as scan_date,
						COUNT(*) as total,
						SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
						SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
						SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) as medium,
						SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END) as low
					FROM vul
					WHERE (image = ? OR image LIKE ? || ':%')
					GROUP BY date(processed)
					ORDER BY scan_date
`

	queryCommonVulns = `SELECT
						exposure,
						severity,
						MAX(score) as max_score,
						GROUP_CONCAT(DISTINCT image) as images
					FROM vul
					WHERE image IN (%s)
					GROUP BY exposure
					HAVING COUNT(DISTINCT image) > 1
					ORDER BY max_score DESC
`
)

// Query returns all rows from the table.
func Query(ctx context.Context, opt *query.Options) (any, error) {
	if opt == nil {
		return nil, errors.New("options are required")
	}

	db, err := getStore(ctx, opt.Target)
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
	case query.Undefined:
		return nil, errors.New("undefined query type")
	case query.Images:
		q = querySummary
		a = []any{nil, nil, nil} // All three params null for "all images"
	case query.Digests:
		q = querySummary
		a = []any{opt.Image, opt.Image, opt.Image} // image param 3x for: IS NULL check, exact match, LIKE
	case query.Exposure:
		q = queryExposures
		a = []any{opt.Image, opt.Image, opt.Digest} // image 2x for: exact match, LIKE
	case query.Packages:
		q = queryPackages
		a = []any{opt.Image, opt.Image, opt.Digest, opt.Exposure} // image 2x for: exact match, LIKE
	case query.TimeSeries:
		q = queryTimeSeries
		a = []any{opt.Image, opt.Image} // image 2x for: exact match, LIKE
	case query.CommonVulns:
		// Build placeholder string for IN clause
		placeholders := make([]string, len(opt.Images))
		a = make([]any, len(opt.Images))
		for i, img := range opt.Images {
			placeholders[i] = "?"
			a[i] = img
		}
		q = fmt.Sprintf(queryCommonVulns, strings.Join(placeholders, ","))
	}

	stmt, err := db.PrepareContext(ctx, q)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to prepare select statement")
	}

	rows, err := stmt.QueryContext(ctx, a...)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, errors.Wrapf(err, "failed to execute select statement")
	}
	defer rows.Close()

	switch qt {
	case query.Undefined:
		return nil, errors.New("undefined query type")
	case query.Images:
		return scanSummary(rows)
	case query.Digests:
		return scanSummary(rows)
	case query.Exposure:
		return scanExposure(opt, rows)
	case query.Packages:
		return scanPackages(opt, rows)
	case query.TimeSeries:
		return scanTimeSeries(opt, rows)
	case query.CommonVulns:
		return scanCommonVulns(opt, rows)
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

	slog.Info("found records", "count", len(r))

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
		if query.HasUniqueExposureSeverityScore(v) {
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

	slog.Info("found records", "count", len(r.Packages))

	return r, nil
}

func scanTimeSeries(opt *query.Options, rows *sql.Rows) (any, error) {
	r := &query.TimeSeriesResult{
		Image:      opt.Image,
		DataPoints: make([]*query.TimeSeriesDataPoint, 0),
	}

	for rows.Next() {
		var date string
		var total, critical, high, medium, low int

		if err := rows.Scan(&date, &total, &critical, &high, &medium, &low); err != nil {
			return nil, errors.Wrapf(err, "failed to scan timeseries row")
		}

		r.DataPoints = append(r.DataPoints, &query.TimeSeriesDataPoint{
			Date:     date,
			Total:    total,
			Critical: critical,
			High:     high,
			Medium:   medium,
			Low:      low,
		})
	}

	slog.Info("found data points", "count", len(r.DataPoints))

	return r, nil
}

func scanCommonVulns(opt *query.Options, rows *sql.Rows) (any, error) {
	r := &query.CommonVulnsResult{
		Images: opt.Images,
		Common: make(map[string]*query.CommonVulnInfo),
	}

	for rows.Next() {
		var exposure, severity, imagesStr string
		var score float32

		if err := rows.Scan(&exposure, &severity, &score, &imagesStr); err != nil {
			return nil, errors.Wrapf(err, "failed to scan common vulns row")
		}

		r.Common[exposure] = &query.CommonVulnInfo{
			Severity:       severity,
			Score:          score,
			AffectedImages: strings.Split(imagesStr, ","),
		}
	}

	slog.Info("found common vulnerabilities", "count", len(r.Common))

	return r, nil
}
