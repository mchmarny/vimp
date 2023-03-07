package vul

import (
	"context"
	"fmt"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"github.com/mchmarny/vulctl/pkg/convert"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	g "google.golang.org/genproto/googleapis/grafeas/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	for noteID, nocc := range list {
		if err := postNoteOccurrences(ctx, opt.Project, noteID, nocc); err != nil {
			return errors.Wrap(err, "error posting notes")
		}
	}

	return nil
}

// postNoteOccurrences creates new Notes and its associated Occurrences.
// Notes will be created only if it does not exist.
func postNoteOccurrences(ctx context.Context, projectID string, noteID string, nocc types.NoteOccurrences) error {
	if projectID == "" {
		return errors.New("projectID required")
	}

	// don't submit end-to-end test
	if projectID == types.TestProjectID {
		return nil
	}

	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return errors.Wrap(err, "error creating client")
	}
	defer c.Close()

	p := fmt.Sprintf("projects/%s", projectID)

	// Create Note
	req := &g.CreateNoteRequest{
		Parent: p,
		NoteId: noteID,
		Note:   nocc.Note,
	}
	noteName := fmt.Sprintf("%s/notes/%s", p, noteID)
	_, err = c.GetGrafeasClient().CreateNote(ctx, req)
	if err != nil {
		// If note already exists, skip
		if status.Code(err) == codes.AlreadyExists {
			log.Info().Msgf("Already Exists: %s", noteName)
		} else {
			return errors.Wrap(err, "error posting note")
		}
	} else {
		log.Info().Msgf("Created: %s", noteName)
	}

	// Create Occurrences
	for _, o := range nocc.Occurrences {
		o.NoteName = noteName
		req := &g.CreateOccurrenceRequest{
			Parent:     p,
			Occurrence: o,
		}
		occ, err := c.GetGrafeasClient().CreateOccurrence(ctx, req)
		if err != nil {
			// If occurrence already exists, skip
			if status.Code(err) == codes.AlreadyExists {
				log.Info().Msgf("Already Exists: Occurrence %s-%s",
					o.GetVulnerability().PackageIssue[0].AffectedPackage,
					o.GetVulnerability().PackageIssue[0].AffectedVersion.Name)
			} else {
				return errors.Wrap(err, "error posting occurrence")
			}
		} else {
			log.Info().Msgf("Created: %s", occ.Name)
		}
	}

	/*
		// Batch create Occurrences
		// TODO: Batch create is slower by a signifant margin than individually creating Occurrences. Why?
		for _, o := range nocc.Occurrences {
			o.NoteName = noteName
		}

		oreq := &g.BatchCreateOccurrencesRequest{
			Parent: p,
			Occurrences: nocc.Occurrences,
		}
		bres, err := c.GetGrafeasClient().BatchCreateOccurrences(ctx, oreq)
		if err != nil {
			// TODO: figure out how to handle batch errors
			log.Debug().Msgf("BatchCreateOccurrences error ignored: %s", err)
		} else {
			log.Info().Msgf("Created: %s Occurrences", len(bres.Occurrences))
		}
	*/

	return nil
}
