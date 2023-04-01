package processor

import (
	"net/url"
	"strings"

	"github.com/mchmarny/vulctl/internal/parser"
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
	Format *string

	// FormatType is the type of the format (e.g. json, yaml, etc.)
	FormatType Format

	// Output path (optional).
	Output *string

	// Quiet suppresses output
	Quiet bool

	uri    string
	digest string
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

	if strings.Contains(o.Source, "@") {
		parts := strings.Split(o.Source, "@")
		o.uri = parts[0]
		o.digest = parts[1]
	} else {
		if strings.Contains(o.Source, ":") {
			parts := strings.Split(o.Source, ":")
			o.uri = parts[0]
		} else {
			o.uri = o.Source
		}
	}

	if o.File == "" {
		return ErrMissingPath
	}
	if o.Format == nil || *o.Format == "" {
		c, err := parser.GetContainer(o.File)
		if err != nil {
			return errors.Wrap(err, "error parsing file while discovering format")
		}
		f := discoverFormat(c)
		o.FormatType = f

	} else {
		f, err := ParseFormat(*o.Format)
		if err != nil {
			return errors.Wrap(err, "error parsing format")
		}
		o.FormatType = f
	}

	if o.FormatType == FormatUnknown {
		return ErrMissingFormat
	}

	return nil
}
