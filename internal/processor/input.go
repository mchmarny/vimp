package processor

import (
	"net/url"

	"github.com/mchmarny/vulctl/internal/source"
	"github.com/pkg/errors"
)

const (
	TestProjectID = "test"
)

var (
	ErrMissingFormat = errors.New("missing format")
	ErrMissingPath   = errors.New("missing path")
	ErrMissingSource = errors.New("missing source")
	ErrInvalidSource = errors.New("invalid source")
)

// Options represents the input options.
type Options struct {
	// Source is the URI of the image from which the report was generated.
	Source string

	// File path to the vulnerability report to import.
	File string

	// Format of the file to import.
	Format string

	// FormatType is the type of the format (e.g. json, yaml, etc.)
	FormatType source.Format

	// Output path (optional).
	Output *string

	// Quiet suppresses output
	Quiet bool
}

func (o *Options) validate() error {
	// Validate URL and ensure that scheme is specified
	if o.Source == "" {
		return ErrMissingSource
	}
	u, err := url.Parse(o.Source)
	if err != nil {
		return errors.Wrap(ErrInvalidSource, err.Error())
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	o.Source = u.String()

	if o.File == "" {
		return ErrMissingPath
	}
	if o.Format == "" {
		return ErrMissingFormat
	}

	f, err := source.ParseFormat(o.Format)
	if err != nil {
		return errors.Wrap(err, "error parsing format")
	}

	o.FormatType = f

	return nil
}
