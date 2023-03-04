package vul

import (
	"context"

	"github.com/mchmarny/vulctl/pkg/convert"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

func Import(ctx context.Context, opt *types.ImportOptions) error {
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

	vuls, err := c(ctx, s)
	if err != nil {
		return errors.Wrap(err, "error converting source")
	}

	if vuls == nil {
		return errors.New("expected non-nil result")
	}

	for _, v := range vuls {
		log.Debug().Interface("vul", v).Msg("vulnerabilities")
	}

	return nil
}
