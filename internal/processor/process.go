package processor

import (
	"encoding/csv"
	"encoding/json"
	"os"

	"github.com/mchmarny/vulctl/internal/parser"
	"github.com/mchmarny/vulctl/pkg/data"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

func Process(opt *Options) error {
	if opt == nil {
		return errors.New("options required")
	}
	if err := opt.validate(); err != nil {
		return errors.Wrap(err, "error validating options")
	}

	m, err := getMapper(opt.FormatType)
	if err != nil {
		return errors.Wrap(err, "error getting converter")
	}

	c, err := parser.GetContainer(opt.File)
	if err != nil {
		return errors.Wrap(err, "error parsing source")
	}

	list, err := m(c)
	if err != nil {
		return errors.Wrap(err, "error converting source")
	}

	if list == nil {
		return errors.New("expected non-nil result")
	}

	uniques := Unique(list)
	log.Info().Msgf("found %d vulnerabilities", len(uniques))

	data := data.DecorateVulnerabilities(uniques, opt.uri, opt.digest, opt.FormatType.String())

	// stdout
	if opt.Output == nil || *opt.Output == "" {
		if err := output(opt, data); err != nil {
			return errors.Wrap(err, "error outputting the processed data")
		}
		return nil
	}

	if opt.CSV {
		if err := writeCSV(*opt.Output, data); err != nil {
			return errors.Wrap(err, "error writing the processed data to CSV")
		}
		return nil
	}

	if err := writeJSON(*opt.Output, data); err != nil {
		return errors.Wrap(err, "error writing the processed data to JSON")
	}

	return nil
}

// output writes the results to stdout.
func output(in *Options, results []*data.ImageVulnerability) error {
	if in == nil {
		return errors.New("options required")
	}

	je := json.NewEncoder(os.Stdout)
	je.SetIndent("", "  ")
	if err := je.Encode(results); err != nil {
		return errors.Wrap(err, "error encoding the output to stdout")
	}

	return nil
}

// writeJSON writes the results to a file.
func writeJSON(path string, results []*data.ImageVulnerability) error {
	if path == "" {
		return errors.New("path required")
	}

	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return errors.Wrap(err, "error marshaling the output to file")
	}

	if err := os.WriteFile(path, b, 0600); err != nil {
		return errors.Wrapf(err, "error writing the output to file: %s", path)
	}

	return nil
}

// writeCSV writes the results to a file.
func writeCSV(path string, results []*data.ImageVulnerability) error {
	if path == "" {
		return errors.New("path required")
	}

	// file
	f, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "error creating the output file: %s", path)
	}
	defer f.Close()

	// csv
	w := csv.NewWriter(f)

	for _, r := range results {
		if err := w.Write(r.Strings()); err != nil {
			return errors.Wrap(err, "error writing record to file")
		}
	}

	w.Flush()

	if err := w.Error(); err != nil {
		return errors.Wrap(err, "error writing the output to file")
	}

	return nil
}
