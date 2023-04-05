package sqlite

import (
	"database/sql"
	"time"

	"github.com/mchmarny/vimp/pkg/query"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var (
	queryAllImages = `SELECT DISTINCT image FROM vul ORDER BY image`
	queryDigests   = `SELECT DISTINCT image, digest FROM vul WHERE image = ? ORDER BY digest`
	queryCVEs      = `SELECT
						cve,
						source,
						severity,
						score,
						MAX(processed) last_processed
					FROM vul
					WHERE image = ?
					AND digest = ?
					GROUP BY cve, source, severity, score
					ORDER BY 1, 2
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
					AND cve = ?
					GROUP BY source, package, version, severity, score
					ORDER BY 1, 2, 3
`
)

// Query returns all rows from the table.
// TODO: implement
func Query(opt *query.Options) (any, error) {
	if opt == nil {
		return nil, errors.New("options are required")
	}

	log.Debug().Str("options", opt.String()).Msg("Query")

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

	log.Debug().Str("query", qt.String()).Msg("Query")

	switch qt {
	case query.Images:
		q = queryAllImages
		a = nil
	case query.Digests:
		q = queryDigests
		a = []interface{}{opt.Image}
	case query.CVEs:
		q = queryCVEs
		a = []interface{}{opt.Image, opt.Digest}
	case query.Packages:
		q = queryPackages
		a = []interface{}{opt.Image, opt.Digest, opt.CVE}
	default:
		return nil, errors.Errorf("unsupported query type: %v", qt)
	}

	log.Debug().Str("sql", q).Msgf("Query: %v", a)

	stmt, err := db.Prepare(q)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to prepare select statement")
	}

	var rows *sql.Rows
	if a == nil {
		rows, err = stmt.Query()
	} else {
		rows, err = stmt.Query(a...)
	}

	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, errors.Wrapf(err, "failed to execute select statement")
	}
	defer rows.Close()

	switch qt {
	case query.Images:
		return scanArray(rows)
	case query.Digests:
		return scanImages(rows)
	case query.CVEs:
		return scanCVEs(opt, rows)
	case query.Packages:
		return nil, errors.New("not implemented")
	}

	return nil, errors.Errorf("unsupported query type: %v", qt)
}

func scanImages(rows *sql.Rows) (any, error) {
	m := make([]*query.Image, 0)

	for rows.Next() {
		v := &query.Image{}
		if err := rows.Scan(&v.Image, &v.Digest); err != nil {
			return nil, errors.Wrapf(err, "failed to scan image row")
		}
		m = append(m, v)
	}

	return m, nil
}

func scanCVEs(opt *query.Options, rows *sql.Rows) (any, error) {
	m := make(map[string][]*query.VulnerabilitySource, 0)

	for rows.Next() {
		var cve string
		var source string
		var severity string
		var score float64
		var lastProcessed string

		if err := rows.Scan(&cve, &source, &severity, &score, &lastProcessed); err != nil {
			return nil, errors.Wrapf(err, "failed to scan image row")
		}

		if _, ok := m[cve]; !ok {
			m[cve] = make([]*query.VulnerabilitySource, 0)
		}

		t, err := time.Parse(time.RFC3339Nano, lastProcessed)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing time from %s", lastProcessed)
		}

		m[cve] = append(m[cve], &query.VulnerabilitySource{
			Source:      source,
			Severity:    severity,
			Score:       float32(score),
			IsFixed:     false,
			ProcessedAt: t,
		})
	}

	if opt.DiffsOnly {
		m = query.FilterOutDuplicates(m)
	}

	v := &query.VulnerabilityList{
		Image: &query.Image{
			Image:  opt.Image,
			Digest: opt.Digest,
		},
		Count:           len(m),
		Vulnerabilities: m,
	}

	return v, nil
}

func scanArray(rows *sql.Rows) (any, error) {
	list := make([]any, 0)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, errors.Wrapf(err, "failed to scan image row")
		}
		list = append(list, v)
	}

	return list, nil
}
