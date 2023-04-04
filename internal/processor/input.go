package processor

import (
	"net/url"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vimp/internal/parser"
	"github.com/pkg/errors"
)

// Options represents the input options.
type Options struct {
	// Source is the URI of the image from which the report was generated.
	Source string

	// File path to the vulnerability report to import.
	File string

	// Target is the target data store uri.
	Target string

	// FormatType is the type of the format (e.g. json, yaml, etc.).
	FormatType Format

	container *gabs.Container
	uri       string
	digest    string
}

func (o *Options) validate() error {
	if o.Target == "" {
		return errors.New("target is required")
	}

	if o.Source == "" {
		return errors.New("source is required")
	}

	if !strings.Contains(o.Source, "@") {
		return errors.New("source must contain digest")
	}

	u, err := url.Parse(o.Source)
	if err != nil {
		return errors.Wrap(err, "error parsing source")
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	o.Source = u.String()

	parts := strings.Split(o.Source, "@")
	o.uri = parts[0]
	o.digest = parts[1]

	if o.File == "" {
		return errors.New("file path is required")
	}

	c, err := parser.GetContainer(o.File)
	if err != nil {
		return errors.Wrapf(err, "error parsing file: %s", o.File)
	}
	o.container = c
	f := discoverFormat(c)
	o.FormatType = f

	if o.FormatType == FormatUnknown {
		return errors.New("unknown source file format, supported formats are: grype, snyk, trivy")
	}

	return nil
}
