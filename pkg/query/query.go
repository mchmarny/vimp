package query

import (
	"fmt"
	"strings"

	"github.com/mchmarny/vimp/internal/config"
	"github.com/pkg/errors"
)

const (
	// TypeImage represents the image query type.
	Undefined Query = iota
	Images
	Digests
	Exposure
	Packages
	TimeSeries  // Vulnerability count over time for an image
	CommonVulns // CVEs shared across multiple images
)

// OutputFormat represents the output format for query results.
type OutputFormat int64

const (
	FormatJSON OutputFormat = iota
	FormatSARIF
)

// String returns the string representation of the output format.
func (f OutputFormat) String() string {
	switch f {
	case FormatJSON:
		return "json"
	case FormatSARIF:
		return "sarif"
	}
	return "json"
}

// ParseOutputFormat parses an output format from a string.
func ParseOutputFormat(s string) OutputFormat {
	switch strings.ToLower(s) {
	case "sarif":
		return FormatSARIF
	default:
		return FormatJSON
	}
}

// Type represents the query type.
type Query int64

// String returns the string representation of the query type.
func (q Query) String() string {
	switch q {
	case Undefined:
		return "undefined"
	case Images:
		return "images"
	case Digests:
		return "digests"
	case Exposure:
		return "exposure"
	case Packages:
		return "packages"
	case TimeSeries:
		return "timeseries"
	case CommonVulns:
		return "common"
	}
	return "undefined"
}

// Options represents the input options.
type Options struct {
	// Image is the URI of the image from which the report was generated.
	Image string

	// Digest is the sha:256 digest of the image.
	Digest string

	// Exposure is the CVE ID to query.
	Exposure string

	// Target is the target data store uri.
	Target string

	// DiffsOnly indicates if only diffs should be returned.
	DiffsOnly bool

	// Format is the output format (json, sarif).
	Format OutputFormat

	// QueryType is the explicit query type (optional, auto-detected if not set).
	QueryType Query

	// Images is a list of images for cross-image queries.
	Images []string

	// StartDate is the start date for time-series queries.
	StartDate string

	// EndDate is the end date for time-series queries.
	EndDate string
}

func (o *Options) String() string {
	return fmt.Sprintf("image: %s, digest: %s, exposure: %s, target: %s, diffsOnly: %t}",
		o.Image, o.Digest, o.Exposure, o.Target, o.DiffsOnly)
}

// GetQuery returns the query type.
//
//nolint:unparam // error return kept for future validation
func (o *Options) GetQuery() (Query, error) {
	// Use explicit query type if set
	if o.QueryType != Undefined {
		return o.QueryType, nil
	}

	// Check for cross-image queries
	if len(o.Images) > 0 {
		return CommonVulns, nil
	}

	// Check for time-series query (has date range)
	if o.StartDate != "" || o.EndDate != "" {
		return TimeSeries, nil
	}

	// Auto-detect based on what's set
	// if nothing set, return all images
	if o.Exposure == "" && o.Digest == "" && o.Image == "" {
		return Images, nil
	}

	if o.Exposure == "" && o.Digest == "" {
		return Digests, nil
	}

	if o.Exposure == "" {
		return Exposure, nil
	}

	return Packages, nil
}

// Validate validates the options.
func (o *Options) Validate() error {
	if o.Image != "" {
		if strings.Contains(o.Image, "@") {
			imageParts := strings.Split(o.Image, "@")
			o.Image = imageParts[0]
			o.Digest = imageParts[1]
		}

		var err error
		o.Image, err = config.RemoveSchema(o.Image)
		if err != nil {
			return errors.Wrap(err, "invalid image format")
		}

		// Normalize simple image names to docker.io/library/ prefix
		// This matches the normalization done during import
		o.Image = config.NormalizeImageName(o.Image)
	}

	if o.Target == "" {
		o.Target = config.GetDefaultDBPath()
	}

	return nil
}
