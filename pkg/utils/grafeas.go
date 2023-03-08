package utils

import (
	"strings"

	g "google.golang.org/genproto/googleapis/grafeas/v1"
)

func ToGrafeasSeverity(s string) g.Severity {
	if s == "" {
		return g.Severity_SEVERITY_UNSPECIFIED
	}

	switch strings.ToUpper(s) {
	case "CRITICAL":
		return g.Severity_CRITICAL
	case "HIGH":
		return g.Severity_HIGH
	case "MEDIUM":
		return g.Severity_MEDIUM
	case "LOW":
		return g.Severity_LOW
	case "MINOR":
		return g.Severity_MINIMAL
	default:
		return g.Severity_SEVERITY_UNSPECIFIED
	}
}
