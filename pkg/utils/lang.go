package utils

import "strings"

// ParsePackageType parses package type from string.
// If package type is not recognized, returns "LIB".
func ParsePackageType(v string) string {
	switch strings.ToLower(v) {
	case "gobinary":
		return "Go"
	case "npm":
		return "NPM"
	case "rubygems":
		return "RUBYGEMS"
	case "python":
		return "PIP"
	case "maven":
		return "MAVEN"
	case "nuget":
		return "NUGET"
	case "pipenv":
		return "PIPENV"
	case "poetry":
		return "POETRY"
	case "sbt":
		return "SBT"
	case "gradle":
		return "GRADLE"
	case "yarn":
		return "YARN"
	case "cargo":
		return "CARGO"
	default:
		return "LIB"
	}
}
