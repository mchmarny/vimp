package vul

import (
	"context"
	"fmt"

	"github.com/mchmarny/vulctl/pkg/convert"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	aa "google.golang.org/api/containeranalysis/v1"
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

	list, err := c(ctx, s)
	if err != nil {
		return errors.Wrap(err, "error converting source")
	}

	if list == nil {
		return errors.New("expected non-nil result")
	}

	if err := postNotes(ctx, opt.Project, list); err != nil {
		return errors.Wrap(err, "error posting notes")
	}

	return nil
}

func postNotes(ctx context.Context, projectID string, notes []*aa.Note) error {
	s, err := aa.NewService(ctx)
	if err != nil {
		return errors.Wrap(err, "error creating service")
	}

	r := &aa.BatchCreateNotesRequest{
		Notes: make(map[string]aa.Note, 0),
	}

	for _, n := range notes {
		r.Notes["string"] = *n
		log.Info().Msgf("%s - %s: %f - %s", n.Name, n.Vulnerability.Details[0].AffectedPackage,
			n.Vulnerability.CvssScore, n.ShortDescription)
	}

	p := fmt.Sprintf("projects/%s", projectID)

	cc := s.Projects.Notes.BatchCreate(p, r)

	// don't submit end-to-end
	if projectID == types.TestProjectID {
		return nil
	}

	nr, err := cc.Do()
	if err != nil {
		return errors.Wrap(err, "error posting notes")
	}

	log.Info().Msgf("Notes created: %d", len(nr.Notes))
	for _, n := range nr.Notes {
		log.Info().Msgf("Created: %s", n.Name)
	}

	return nil
}
