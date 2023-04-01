package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSha(t *testing.T) {
	want := "28049ef2189126dff18e6a8956ddfa5a0e45c12e8babe4067da1660bf660d9cc"
	item := &Vulnerability{
		ID:      "CVE-2019-0001",
		Package: "test",
		Version: "1.0.0",
	}

	assert.Equal(t, want, item.GetSHA256())

	item.Version = "1.0.1"

	assert.NotEqual(t, want, item.GetSHA256())
}
