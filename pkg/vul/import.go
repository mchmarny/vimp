package vul

import (
	"context"
	"fmt"

	ca "cloud.google.com/go/containeranalysis/apiv1"
	"github.com/mchmarny/vulctl/pkg/convert"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/iterator"
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

	// TODO: Debug code
	//deleteNoteOccurrences(ctx, opt, list)

	log.Info().Msgf("Found %d vulnerabilities", len(list))

	if list == nil {
		return errors.New("expected non-nil result")
	}

	for noteID, nocc := range list {
		log.Debug().Msgf("Note: %s, Occurrences: %d", noteID, len(nocc.Occurrences))
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

	c, err := ca.NewClient(ctx)
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

	return nil
}

// deleteNoteOccurrences deletes notes and occurrences. Used for debugging.
// nolint:unused
func deleteNoteOccurrences(ctx context.Context, opt *types.ImportOptions, list map[string]types.NoteOccurrences) error {
	c, err := ca.NewClient(ctx)
	if err != nil {
		return errors.Wrap(err, "error creating client")
	}
	defer c.Close()

	p := fmt.Sprintf("projects/%s", opt.Project)

	// Delete Notes
	for noteID := range list {
		noteName := fmt.Sprintf("%s/notes/%s", p, noteID)

		dr := &g.DeleteNoteRequest{
			Name: noteName,
		}
		_ = c.GetGrafeasClient().DeleteNote(ctx, dr)
	}

	// Delete Occurrences
	req := &g.ListOccurrencesRequest{
		Parent:   p,
		Filter:   fmt.Sprintf("resource_url=\"%s\"", opt.Source),
		PageSize: 1000,
	}
	it := c.GetGrafeasClient().ListOccurrences(ctx, req)
	for {
		resp, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return err
		}

		dr := &g.DeleteOccurrenceRequest{
			Name: resp.Name,
		}
		_ = c.GetGrafeasClient().DeleteOccurrence(ctx, dr)
	}

	return nil
}
