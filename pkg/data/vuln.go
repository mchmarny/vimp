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
	// CVE is the vulnerability ID.
	CVE string `json:"cve,omitempty"`

	// Package is the package name.
	Package string `json:"package,omitempty"`

	// Version is the package version.
	Version string `json:"version,omitempty"`

	// Severity is the vulnerability severity.
	Severity string `json:"severity,omitempty"`

	// Score is the vulnerability score.
	Score float32 `json:"score,omitempty"`

	// Is Fixed indicates of the vulnerability has been fixed.
	IsFixed bool `json:"fixed,omitempty"`
}

func (v *Vulnerability) String() string {
	return fmt.Sprintf("%s/%s/%s/%s/%f/%t", v.CVE, v.Package, v.Version, v.Severity, v.Score, v.IsFixed)
}

func (v *Vulnerability) GetSHA256() string {
	s := fmt.Sprintf("%s%s%s%s%s", v.CVE, ShaConcatChar, v.Package, ShaConcatChar, v.Version)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}
