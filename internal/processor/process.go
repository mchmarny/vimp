package processor

import (
	"github.com/mchmarny/vimp/internal/target"
	"github.com/mchmarny/vimp/pkg/data"
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

	t, err := target.GetImporter(opt.Target)
	if err != nil {
		return errors.Wrap(err, "error getting importer")
	}

	list, err := m(opt.container)
	if err != nil {
		return errors.Wrap(err, "error converting source")
	}

	if list == nil {
		return errors.New("expected non-nil result")
	}

	uniques := Unique(list)
	log.Info().Msgf("found %d unique vulnerabilities", len(uniques))

	data := data.DecorateVulnerabilities(uniques, opt.uri, opt.digest, opt.FormatType.String())

	if err := t(opt.Target, data); err != nil {
		return errors.Wrapf(err, "error importing data to: %s", opt.Target)
	}

	return nil
}
