package processor

import (
	"encoding/json"
	"os"
	"time"

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

	c, err := getMapper(opt.FormatType)
	if err != nil {
		return errors.Wrap(err, "error getting converter")
	}

	list, err := c(opt.File)
	if err != nil {
		return errors.Wrap(err, "error converting source")
	}

	if list == nil {
		return errors.New("expected non-nil result")
	}

	uniques := Unique(list)
	log.Info().Msgf("found %d vulnerabilities", len(uniques))

	scan := &data.Scan{
		URI:             opt.Source,
		Digest:          "",
		PerformedAt:     time.Now().UTC(),
		Count:           len(uniques),
		Vulnerabilities: uniques,
	}

	if err := output(opt, scan); err != nil {
		return errors.Wrap(err, "error outputting the processed data")
	}

	return nil
}

func output(in *Options, result *data.Scan) error {
	if in == nil {
		return errors.New("options required")
	}
	if result == nil {
		return errors.New("vulnerabilities required")
	}

	log.Debug().Msgf("found: %d", result.Count)

	// output to stdout
	if in.Output == nil || *in.Output == "" {
		je := json.NewEncoder(os.Stdout)
		je.SetIndent("", "  ")
		if err := je.Encode(result); err != nil {
			return errors.Wrap(err, "error encoding the output to stdout")
		}
		return nil
	}

	// output to file
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return errors.Wrap(err, "error marshaling the output to file")
	}

	if err := os.WriteFile(*in.Output, b, 0600); err != nil {
		return errors.Wrapf(err, "error writing the output to file: %s", *in.Output)
	}

	return nil
}
