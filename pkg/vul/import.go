package vul

import (
	"encoding/json"
	"os"

	"github.com/mchmarny/vulctl/pkg/convert"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

func Import(opt *types.InputOptions) error {
	if opt == nil {
		return errors.New("options required")
	}
	if err := opt.Validate(); err != nil {
		return errors.Wrap(err, "error validating options")
	}
	s, err := src.NewSource(opt)
	if err != nil {
		return errors.Wrap(err, "error creating source")
	}

	c, err := convert.GetConverter(opt.Format)
	if err != nil {
		return errors.Wrap(err, "error getting converter")
	}

	list, err := c(s)
	if err != nil {
		return errors.Wrap(err, "error converting source")
	}

	log.Info().Msgf("found %d vulnerabilities", len(list))

	if list == nil {
		return errors.New("expected non-nil result")
	}

	if err := output(opt, list); err != nil {
		return errors.Wrap(err, "error posting notes")
	}

	return nil
}

func output(in *types.InputOptions, vuls map[string]*types.Vulnerability) error {
	if in == nil {
		return errors.New("options required")
	}
	if vuls == nil {
		return errors.New("vulnerabilities required")
	}

	log.Debug().Msgf("found: %d", len(vuls))

	list := make([]*types.Vulnerability, 0, len(vuls))
	for _, v := range vuls {
		list = append(list, v)
	}

	if in.Output == nil {
		if err := json.NewEncoder(os.Stdout).Encode(list); err != nil {
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
