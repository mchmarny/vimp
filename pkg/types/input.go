package types

import (
	"net/url"

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

type InputOptions struct {
	// Source is the URI of the image from which the report was generated.
	Source string

	// File path to the vulnerability report to import.
	File string

	// Format of the file to import.
	Format SourceFormat

	// Output path (optional).
	Output *string

	// Quiet suppresses output
	Quiet bool
}

func (i *InputOptions) Validate() error {
	// Validate URL and ensure that scheme is specified
	if i.Source == "" {
		return ErrMissingSource
	}
	u, err := url.Parse(i.Source)
	if err != nil {
		return errors.Wrap(ErrInvalidSource, err.Error())
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	i.Source = u.String()

	if i.File == "" {
		return ErrMissingPath
	}
	if i.Format == SourceFormatUnknown {
		return ErrMissingFormat
	}
	return nil
}
