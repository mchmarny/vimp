package types

import (
	"net/url"

	"github.com/pkg/errors"
)

const (
	TestProjectID = "test"
)

var (
	ErrMissingProject = errors.New("missing project")
	ErrMissingFormat  = errors.New("missing format")
	ErrMissingPath    = errors.New("missing path")
	ErrMissingSource  = errors.New("missing source")
	ErrInvalidSource  = errors.New("invalid source")
)

type ImportOptions struct {
	// Project is the ID of the project to import the report into.
	Project string

	// Source is the URI of the image from which the report was generated.
	Source string

	// File path to the vulnerability report to import.
	File string

	// Format of the file to import.
	Format SourceFormat

	// Quiet suppresses output
	Quiet bool
}

func (i *ImportOptions) Validate() error {
	if i.Project == "" {
		return ErrMissingProject
	}

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
