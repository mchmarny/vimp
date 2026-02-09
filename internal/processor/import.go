package processor

import (
	"context"
	"log/slog"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vimp/internal/config"
	"github.com/mchmarny/vimp/internal/converter"
	"github.com/mchmarny/vimp/internal/parser"
	"github.com/mchmarny/vimp/internal/scanner"
	"github.com/mchmarny/vimp/internal/target"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

// ImportOptions represents the input options.
type ImportOptions struct {
	// Source is the URI of the image from which the report was generated.
	Source string

	// File path to the vulnerability report to import.
	File string

	// Scanners is the list of scanners to use.
	Scanners string

	// Target is the target data store uri.
	Target string

	container         *gabs.Container
	uri               string
	digest            string
	detectedConverter converter.Converter
}

func (o *ImportOptions) validate(_ context.Context) error {
	if o.Source == "" {
		return errors.New("source is required")
	}

	if o.Target == "" {
		o.Target = config.GetDefaultDBPath()
	}

	var err error
	if !strings.Contains(o.Source, "@") {
		o.Source, err = config.GetDigest(o.Source)
		if err != nil {
			return errors.Wrap(err, "error getting digest")
		}
	}

	o.Source, err = config.RemoveSchema(o.Source)
	if err != nil {
		return errors.Wrap(err, "invalid source format")
	}

	// if image is set with digest, split it and set the digest
	parts := strings.Split(o.Source, "@")
	o.uri = parts[0] // Store full image reference including tag
	o.digest = parts[1]

	if o.File == "" {
		return errors.New("file path is required")
	}

	slog.Info("importing", "image", o.uri, "digest", o.digest, "target", o.Target)

	c, err := parser.GetContainer(o.File)
	if err != nil {
		return errors.Wrapf(err, "error parsing file: %s", o.File)
	}
	o.container = c

	// Detect the format using the converter registry
	conv, err := defaultRegistry.Detect(c)
	if err != nil {
		return errors.New("unknown source file format, supported formats are: " + strings.Join(GetConverterNames(), ", "))
	}
	o.detectedConverter = conv

	return nil
}

// Import imports the vulnerability report to the target data store.
func Import(opt *ImportOptions) error {
	return ImportWithContext(context.Background(), opt)
}

// ImportWithContext imports the vulnerability report to the target data store with context support.
func ImportWithContext(ctx context.Context, opt *ImportOptions) error {
	if opt == nil {
		return errors.New("options required")
	}

	// if file is set, import it
	if opt.File != "" {
		return runImport(ctx, opt)
	}

	var err error
	opt.Source, err = config.RemoveSchema(opt.Source)
	if err != nil {
		return errors.Wrap(err, "invalid source format")
	}

	// if file is not set, scan the image and import the results
	so := &scanner.Options{
		Image: opt.Source,
		Scans: opt.Scanners,
	}

	r, err := scanner.ScanWithContext(ctx, so)
	if err != nil {
		return errors.Wrap(err, "error scanning image")
	}

	for _, f := range r.Files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		opt.File = f
		if err := runImport(ctx, opt); err != nil {
			return errors.Wrap(err, "error importing file")
		}
	}

	return nil
}

func runImport(ctx context.Context, opt *ImportOptions) error {
	if opt == nil {
		return errors.New("options required")
	}
	if err := opt.validate(ctx); err != nil {
		return errors.Wrap(err, "error validating options")
	}

	t, err := target.GetImporter(opt.Target)
	if err != nil {
		return errors.Wrap(err, "error getting importer")
	}

	list, err := opt.detectedConverter.Convert(ctx, opt.container)
	if err != nil {
		return errors.Wrap(err, "error converting source")
	}

	if list == nil {
		return errors.New("expected non-nil result")
	}

	uniques := unique(list)
	slog.Info("found unique vulnerabilities", "count", len(uniques))

	vulnData := data.DecorateVulnerabilities(uniques, opt.uri, opt.digest, opt.detectedConverter.Name())

	if err := t(ctx, opt.Target, vulnData); err != nil {
		return errors.Wrapf(err, "error importing data to: %s", opt.Target)
	}

	return nil
}
