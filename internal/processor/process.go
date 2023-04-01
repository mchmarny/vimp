package processor

import (
	"encoding/json"
	"os"

	"github.com/mchmarny/vulctl/internal/converter"
	"github.com/mchmarny/vulctl/internal/source"
	"github.com/mchmarny/vulctl/pkg/vulnerability"
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
	s, err := source.NewJSONSource(opt.File)
	if err != nil {
		return errors.Wrap(err, "error creating source")
	}

	c, err := converter.GetMapper(opt.FormatType)
	if err != nil {
		return errors.Wrap(err, "error getting converter")
	}

	list, err := c(s)
	if err != nil {
		return errors.Wrap(err, "error converting source")
	}

	if list == nil {
		return errors.New("expected non-nil result")
	}

	uniques := vulnerability.Unique(list)
	log.Info().Msgf("found %d vulnerabilities", len(uniques))

	if err := output(opt, uniques); err != nil {
		return errors.Wrap(err, "error outputting the processed data")
	}

	return nil
}

func output(in *Options, list []*vulnerability.Item) error {
	if in == nil {
		return errors.New("options required")
	}
	if list == nil {
		return errors.New("vulnerabilities required")
	}

	log.Debug().Msgf("found: %d", len(list))

	if in.Output == nil || *in.Output == "" {
		je := json.NewEncoder(os.Stdout)
		je.SetIndent("", "  ")
		if err := je.Encode(list); err != nil {
			return errors.Wrap(err, "error encoding the output to stdout")
		}
		return nil
	}

	b, err := json.Marshal(list)
	if err != nil {
		return errors.Wrap(err, "error marshaling the output to file")
	}

	if err := os.WriteFile(*in.Output, b, 0600); err != nil {
		return errors.Wrapf(err, "error writing the output to file: %s", *in.Output)
	}

	return nil
}
