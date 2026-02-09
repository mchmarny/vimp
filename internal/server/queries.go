package server

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// DashboardStats contains overall statistics for the dashboard.
type DashboardStats struct {
	TotalImages    int       `json:"total_images"`
	TotalDigests   int       `json:"total_digests"`
	TotalExposures int       `json:"total_exposures"`
	TotalPackages  int       `json:"total_packages"`
	LastScan       time.Time `json:"last_scan"`
	CriticalCount  int       `json:"critical_count"`
	HighCount      int       `json:"high_count"`
	MediumCount    int       `json:"medium_count"`
	LowCount       int       `json:"low_count"`
	FixableCount   int       `json:"fixable_count"`
	UnfixableCount int       `json:"unfixable_count"`
}

// RegistryStat contains statistics for a single registry.
type RegistryStat struct {
	Registry      string `json:"registry"`
	ImageCount    int    `json:"image_count"`
	ExposureCount int    `json:"exposure_count"`
}

// RecentImage contains information about a recently scanned image.
type RecentImage struct {
	Image     string    `json:"image"`
	Digest    string    `json:"digest"`
	LastScan  time.Time `json:"last_scan"`
	Exposures int       `json:"exposures"`
	MaxScore  float32   `json:"max_score"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
	Low       int       `json:"low"`
}

// ImageDetail contains detailed information about an image.
type ImageDetail struct {
	Image   string        `json:"image"`
	Digests []*DigestInfo `json:"digests"`
}

// DigestInfo contains information about a specific digest.
type DigestInfo struct {
	Digest    string    `json:"digest"`
	LastScan  time.Time `json:"last_scan"`
	Exposures int       `json:"exposures"`
	Packages  int       `json:"packages"`
	MaxScore  float32   `json:"max_score"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
	Low       int       `json:"low"`
	Sources   []string  `json:"sources"`
}

// ExposureInfo contains information about a vulnerability exposure.
type ExposureInfo struct {
	Exposure string    `json:"exposure"`
	Severity string    `json:"severity"`
	Score    float32   `json:"score"`
	Package  string    `json:"package"`
	Version  string    `json:"version"`
	Source   string    `json:"source"`
	Fixed    bool      `json:"fixed"`
	LastScan time.Time `json:"last_scan"`
}

// TimeSeriesPoint contains vulnerability counts for a specific date.
type TimeSeriesPoint struct {
	Date     string `json:"date"`
	Total    int    `json:"total"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
}

// Queries encapsulates database queries for the dashboard.
type Queries struct {
	db *sql.DB
}

// NewQueries creates a new Queries instance.
func NewQueries(db *sql.DB) *Queries {
	return &Queries{db: db}
}

// GetDashboardStats returns overall dashboard statistics.
func (q *Queries) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	stats := &DashboardStats{}

	// Get counts
	row := q.db.QueryRowContext(ctx, `
		SELECT
			COUNT(DISTINCT image) as images,
			COUNT(DISTINCT image || '@' || digest) as digests,
			COUNT(DISTINCT exposure) as exposures,
			COUNT(DISTINCT package) as packages,
			MAX(processed) as last_scan
		FROM vul
	`)
	var lastScan sql.NullString
	if err := row.Scan(&stats.TotalImages, &stats.TotalDigests,
		&stats.TotalExposures, &stats.TotalPackages, &lastScan); err != nil {
		return nil, errors.Wrap(err, "failed to get counts")
	}
	if lastScan.Valid {
		stats.LastScan = parseTime(lastScan.String)
	}

	// Get severity counts
	rows, err := q.db.QueryContext(ctx, `
		SELECT severity, COUNT(DISTINCT exposure) as count
		FROM vul
		GROUP BY severity
	`)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get severity counts")
	}
	defer rows.Close()

	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, errors.Wrap(err, "failed to scan severity row")
		}
		switch strings.ToLower(severity) {
		case "critical":
			stats.CriticalCount = count
		case "high":
			stats.HighCount = count
		case "medium":
			stats.MediumCount = count
		case "low":
			stats.LowCount = count
		}
	}

	// Get fixable counts
	row = q.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN fixed = 1 THEN 1 ELSE 0 END), 0) as fixable,
			COALESCE(SUM(CASE WHEN fixed = 0 THEN 1 ELSE 0 END), 0) as unfixable
		FROM (SELECT DISTINCT exposure, fixed FROM vul)
	`)
	if err := row.Scan(&stats.FixableCount, &stats.UnfixableCount); err != nil {
		return nil, errors.Wrap(err, "failed to get fixable counts")
	}

	return stats, nil
}

// GetRegistryStats returns statistics grouped by registry.
func (q *Queries) GetRegistryStats(ctx context.Context, limit int) ([]*RegistryStat, error) {
	rows, err := q.db.QueryContext(ctx, `
		SELECT
			CASE
				WHEN INSTR(image, '/') > 0 THEN SUBSTR(image, 1, INSTR(image, '/') - 1)
				ELSE 'docker.io'
			END as registry,
			COUNT(DISTINCT image) as image_count,
			COUNT(DISTINCT exposure) as exposure_count
		FROM vul
		GROUP BY registry
		ORDER BY image_count DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get registry stats")
	}
	defer rows.Close()

	var results []*RegistryStat
	for rows.Next() {
		stat := &RegistryStat{}
		if err := rows.Scan(&stat.Registry, &stat.ImageCount, &stat.ExposureCount); err != nil {
			return nil, errors.Wrap(err, "failed to scan registry row")
		}
		results = append(results, stat)
	}

	return results, nil
}

// GetRecentImages returns the most recently scanned images.
func (q *Queries) GetRecentImages(ctx context.Context, limit int) ([]*RecentImage, error) {
	rows, err := q.db.QueryContext(ctx, `
		SELECT
			image,
			digest,
			MAX(processed) as last_scan,
			COUNT(DISTINCT exposure) as exposures,
			MAX(score) as max_score,
			SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
			SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
			SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
			SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
		FROM vul
		GROUP BY image, digest
		ORDER BY last_scan DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get recent images")
	}
	defer rows.Close()

	var results []*RecentImage
	for rows.Next() {
		img := &RecentImage{}
		var lastScan string
		if err := rows.Scan(&img.Image, &img.Digest, &lastScan,
			&img.Exposures, &img.MaxScore, &img.Critical, &img.High,
			&img.Medium, &img.Low); err != nil {
			return nil, errors.Wrap(err, "failed to scan recent image row")
		}
		img.LastScan = parseTime(lastScan)
		results = append(results, img)
	}

	return results, nil
}

// SearchImages searches for images matching a pattern.
func (q *Queries) SearchImages(ctx context.Context, pattern string, limit int) ([]*RecentImage, error) {
	// Add wildcards for LIKE pattern
	searchPattern := "%" + pattern + "%"

	rows, err := q.db.QueryContext(ctx, `
		SELECT
			image,
			digest,
			MAX(processed) as last_scan,
			COUNT(DISTINCT exposure) as exposures,
			MAX(score) as max_score,
			SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
			SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
			SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
			SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
		FROM vul
		WHERE image LIKE ?
		GROUP BY image, digest
		ORDER BY last_scan DESC
		LIMIT ?
	`, searchPattern, limit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to search images")
	}
	defer rows.Close()

	var results []*RecentImage
	for rows.Next() {
		img := &RecentImage{}
		var lastScan string
		if err := rows.Scan(&img.Image, &img.Digest, &lastScan,
			&img.Exposures, &img.MaxScore, &img.Critical, &img.High,
			&img.Medium, &img.Low); err != nil {
			return nil, errors.Wrap(err, "failed to scan image row")
		}
		img.LastScan = parseTime(lastScan)
		results = append(results, img)
	}

	return results, nil
}

// GetImageDetail returns detailed information about an image.
func (q *Queries) GetImageDetail(ctx context.Context, image string) (*ImageDetail, error) {
	rows, err := q.db.QueryContext(ctx, `
		SELECT
			digest,
			MAX(processed) as last_scan,
			COUNT(DISTINCT exposure) as exposures,
			COUNT(DISTINCT package) as packages,
			MAX(score) as max_score,
			SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
			SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
			SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
			SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
			GROUP_CONCAT(DISTINCT source) as sources
		FROM vul
		WHERE image = ? OR image LIKE ? || ':%'
		GROUP BY digest
		ORDER BY last_scan DESC
	`, image, image)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get image detail")
	}
	defer rows.Close()

	detail := &ImageDetail{
		Image:   image,
		Digests: make([]*DigestInfo, 0),
	}

	for rows.Next() {
		info := &DigestInfo{}
		var lastScan, sources string
		if err := rows.Scan(&info.Digest, &lastScan, &info.Exposures, &info.Packages,
			&info.MaxScore, &info.Critical, &info.High, &info.Medium, &info.Low, &sources); err != nil {
			return nil, errors.Wrap(err, "failed to scan digest row")
		}
		info.LastScan = parseTime(lastScan)
		info.Sources = strings.Split(sources, ",")
		detail.Digests = append(detail.Digests, info)
	}

	return detail, nil
}

// GetExposures returns exposures for a specific image and digest.
func (q *Queries) GetExposures(ctx context.Context, image, digest string) ([]*ExposureInfo, error) {
	rows, err := q.db.QueryContext(ctx, `
		SELECT
			exposure,
			severity,
			score,
			package,
			version,
			source,
			fixed,
			MAX(processed) as last_scan
		FROM vul
		WHERE (image = ? OR image LIKE ? || ':%') AND digest = ?
		GROUP BY exposure, severity, score, package, version, source, fixed
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
			END,
			score DESC
	`, image, image, digest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get exposures")
	}
	defer rows.Close()

	var results []*ExposureInfo
	for rows.Next() {
		exp := &ExposureInfo{}
		var lastScan string
		var fixed int
		if err := rows.Scan(&exp.Exposure, &exp.Severity, &exp.Score,
			&exp.Package, &exp.Version, &exp.Source, &fixed, &lastScan); err != nil {
			return nil, errors.Wrap(err, "failed to scan exposure row")
		}
		exp.Fixed = fixed == 1
		exp.LastScan = parseTime(lastScan)
		results = append(results, exp)
	}

	return results, nil
}

// GetTimeSeries returns vulnerability counts over time for an image.
func (q *Queries) GetTimeSeries(ctx context.Context, image string) ([]*TimeSeriesPoint, error) {
	rows, err := q.db.QueryContext(ctx, `
		SELECT
			date(processed) as scan_date,
			COUNT(DISTINCT exposure) as total,
			SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
			SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
			SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
			SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
		FROM vul
		WHERE image = ? OR image LIKE ? || ':%'
		GROUP BY date(processed)
		ORDER BY scan_date
	`, image, image)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get time series")
	}
	defer rows.Close()

	var results []*TimeSeriesPoint
	for rows.Next() {
		point := &TimeSeriesPoint{}
		if err := rows.Scan(&point.Date, &point.Total, &point.Critical,
			&point.High, &point.Medium, &point.Low); err != nil {
			return nil, errors.Wrap(err, "failed to scan time series row")
		}
		results = append(results, point)
	}

	return results, nil
}

// parseTime parses an RFC3339 time string.
func parseTime(v string) time.Time {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		// Try without timezone
		t, err = time.Parse("2006-01-02T15:04:05", v)
		if err != nil {
			return time.Time{}
		}
	}
	return t
}
