package query

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterOutDuplicates(t *testing.T) {
	t.Parallel()

	list := map[string][]*VulnerabilitySource{
		"1": {
			{
				Source:   "foo",
				Severity: "high",
				Score:    10.0,
			},
			{
				Source:   "foo",
				Severity: "high",
				Score:    9.0,
			},
			{
				Source:   "foo",
				Severity: "high",
				Score:    10.0,
			},
		},
		"2": {
			{
				Source:   "foo",
				Severity: "high",
				Score:    10.0,
			},
			{
				Source:   "foo",
				Severity: "high",
				Score:    10.0,
			},
			{
				Source:   "foo",
				Severity: "high",
				Score:    10.0,
			},
		},
		"3": {
			{
				Source:   "foo1",
				Severity: "high",
				Score:    10.0,
			},
			{
				Source:   "foo2",
				Severity: "high",
				Score:    10.0,
			},
			{
				Source:   "foo3",
				Severity: "high",
				Score:    10.0,
			},
		},
	}

	out := FilterOutDuplicates(list)
	assert.Len(t, out, 2)
}
