package data

import (
	"crypto/sha256"
	"fmt"
)

const (
	ShaConcatChar = "/"
)

// Vulnerability represents a single vulnerability.
type Vulnerability struct {
	// ID is the vulnerability ID.
	ID string `json:"id"`

	// Package is the package name.
	Package string `json:"package"`

	// Version is the package version.
	Version string `json:"version"`

	// Severity is the vulnerability severity.
	Severity string `json:"severity"`

	// Score is the vulnerability score.
	Score float32 `json:"score"`

	// Is Fixed indicates of the vulnerability has been fixed.
	IsFixed bool `json:"fixed"`
}

func (v *Vulnerability) String() string {
	return fmt.Sprintf("%s/%s/%s/%s/%f/%t", v.ID, v.Package, v.Version, v.Severity, v.Score, v.IsFixed)
}

func (v *Vulnerability) GetSHA256() string {
	s := fmt.Sprintf("%s%s%s%s%s", v.ID, ShaConcatChar, v.Package, ShaConcatChar, v.Version)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}
