package vul

import (
	"context"

	"github.com/mchmarny/vulctl/pkg/ca"
	"github.com/mchmarny/vulctl/pkg/convert"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
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

	t, err := ca.New(ctx, opt.Project, opt.Source)
	if err != nil {
		return errors.Wrap(err, "error creating target service")
	}

	if err := c(ctx, s, t); err != nil {
		return errors.Wrap(err, "error converting source")
	}

	return nil
}
