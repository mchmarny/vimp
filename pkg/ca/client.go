package ca

import (
	"context"
	"fmt"
	"strings"

	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
	api "google.golang.org/api/containeranalysis/v1"
)

const (
	errAlreadyExists = "alreadyExists"
)

// New creates a new Container Analysis client for the given project and image.
func New(ctx context.Context, projectID, imageURI string) (*Client, error) {
	s, err := api.NewService(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "error creating container analysis service")
	}

	return &Client{
		projectID:  projectID,
		noteParent: fmt.Sprintf("projects/%s", projectID),
		imageURI:   imageURI,
		service:    s,
	}, nil
}

type Client struct {
	projectID  string
	noteParent string
	imageURI   string
	service    *api.Service
}

// CreateNote creates a new note for the given CVE and returns its ID
func (c *Client) CreateNote(n *api.Note, cve string) (id *string, err error) {
	if n == nil {
		return nil, errors.New("note required")
	}

	if cve == "" {
		return nil, errors.New("cve required")
	}

	nn := fmt.Sprintf("%s/notes/%s", c.noteParent, cve)

	// Temporary hack to avoid creating notes during tests.
	if c.projectID == types.TestProjectID {
		return &nn, nil
	}

	nc := c.service.Projects.Notes.Create(c.noteParent, n).NoteId(cve)
	if _, err := nc.Do(); err != nil && !existsError(err) {
		return nil, errors.Wrap(err, "error posting note")
	}

	return &nn, nil
}

// CreateOccurrence creates a new occurrence for the given note ID.
func (c *Client) CreateOccurrence(o *api.Occurrence, id string) error {
	if o == nil {
		return errors.New("occurrence required")
	}

	if id == "" {
		return errors.New("note id required")
	}

	// Temporary hack to avoid creating occurrences during tests.
	if c.projectID == types.TestProjectID {
		return nil
	}

	oc := c.service.Projects.Occurrences.Create(c.noteParent, o)
	if _, err := oc.Do(); err != nil && !existsError(err) {
		return errors.Wrap(err, "error posting occurrence")
	}

	return nil
}

// TODO: @mchmarny - use header to check for 409 status code
// rather than the content of the error message.
func existsError(err error) bool {
	return strings.Contains(err.Error(), errAlreadyExists)
}
