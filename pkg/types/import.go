package types

import "errors"

var (
	ErrMissingFormat   = errors.New("missing format")
	ErrMissingPath     = errors.New("missing path")
	ErrMissingImageURI = errors.New("missing image URI")
)

type ImportOptions struct {
	// ImageURI is the ID of the project to import into
	ImageURI string

	// File path to the file to import
	File string

	// Format of the file to import
	Format SourceFormat

	// Quiet suppresses output
	Quiet bool
}

func (i *ImportOptions) Validate() error {
	if i.ImageURI == "" {
		return ErrMissingImageURI
	}
	if i.File == "" {
		return ErrMissingPath
	}
	if i.Format == SourceFormatUnknown {
		return ErrMissingFormat
	}
	return nil
}
