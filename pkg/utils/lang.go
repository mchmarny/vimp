package utils

import "strings"

// ParsePackageType parses package type from string.
func ParsePackageType(v string) string {
	if v == "" {
		return "OS"
	}

	// only map the different ones
	switch strings.ToLower(v) {
	case "gobinary":
		v = "GO"
	case "python":
		v = "PIP"
	}

	return strings.ToUpper(v)
}
