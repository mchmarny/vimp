package vul

import (
	"context"

	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
)

var (
	ErrMissingFormat    = errors.New("missing format")
	ErrMissingPath      = errors.New("missing path")
	ErrMissingProjectID = errors.New("missing project ID")
)

type ImportOptions struct {
	// ProjectID is the ID of the project to import into
	ProjectID string

	// File path to the file to import
	File string

	// Format of the file to import
	Format types.SourceFormat

	// Quiet suppresses output
	Quiet bool
}

func (i *ImportOptions) Validate() error {
	if i.ProjectID == "" {
		return ErrMissingProjectID
	}
	if i.File == "" {
		return ErrMissingPath
	}
	if i.Format == types.SourceFormatUnknown {
		return ErrMissingFormat
	}
	return nil
}

func Import(ctx context.Context, opt *ImportOptions) error {
	return nil
}
