package types

import (
	g "google.golang.org/genproto/googleapis/grafeas/v1"
)

type NoteOccurrences struct {
	// Note that the list of Occurrences points to
	Note *g.Note

	// Occurrences that belong to the Note
	Occurrences []*g.Occurrence
}
