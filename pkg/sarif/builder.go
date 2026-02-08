package sarif

import (
	"fmt"
	"strings"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/mchmarny/vimp/pkg/query"
)

const (
	SchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	Version   = "2.1.0"
)

// FromVulnerabilities converts a slice of ImageVulnerability to a SARIF report.
func FromVulnerabilities(vuls []*data.ImageVulnerability, tool, version string) *Report {
	rules := make([]Rule, 0, len(vuls))
	results := make([]Result, 0, len(vuls))
	ruleIndex := make(map[string]int)

	for _, v := range vuls {
		ruleID := v.Exposure

		// Create rule if not exists
		if _, exists := ruleIndex[ruleID]; !exists {
			ruleIndex[ruleID] = len(rules)
			rules = append(rules, Rule{
				ID:   ruleID,
				Name: ruleID,
				ShortDescription: Message{
					Text: fmt.Sprintf("Vulnerability %s", ruleID),
				},
				FullDescription: Message{
					Text: fmt.Sprintf("Vulnerability %s found in package %s version %s", ruleID, v.Package, v.Version),
				},
				HelpURI: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", ruleID),
				DefaultConfig: DefaultConfig{
					Level: mapSeverityToLevel(v.Severity),
				},
			})
		}

		// Create result
		result := Result{
			RuleID:    ruleID,
			RuleIndex: ruleIndex[ruleID],
			Level:     mapSeverityToLevel(v.Severity),
			Message: Message{
				Text: formatResultMessage(v),
			},
			Locations: []Location{
				{
					LogicalLocations: []LogicalLocation{
						{
							Name:               v.Package,
							FullyQualifiedName: fmt.Sprintf("%s@%s", v.Package, v.Version),
							Kind:               "package",
						},
					},
				},
			},
		}
		results = append(results, result)
	}

	return &Report{
		Schema:  SchemaURI,
		Version: Version,
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           tool,
						Version:        version,
						InformationURI: "https://github.com/mchmarny/vimp",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

// capitalizeFirst capitalizes the first letter of a string.
func capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// mapSeverityToLevel converts vulnerability severity to SARIF level.
// SARIF levels: error, warning, note, none
func mapSeverityToLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "negligible":
		return "note"
	default:
		return "warning"
	}
}

// FromExposureResult converts an ImageExposureResult to a SARIF report.
func FromExposureResult(result *query.ImageExposureResult, tool, version string) *Report {
	// Count total results for preallocation
	totalResults := 0
	for _, sources := range result.Exposures {
		totalResults += len(sources)
	}

	rules := make([]Rule, 0, len(result.Exposures))
	results := make([]Result, 0, totalResults)
	ruleIndex := make(map[string]int)

	for exposure, sources := range result.Exposures {
		// Create rule for this exposure
		if _, exists := ruleIndex[exposure]; !exists {
			ruleIndex[exposure] = len(rules)

			// Get the highest severity/score for the rule
			var maxSeverity string
			var maxScore float32
			for _, s := range sources {
				if s.Score > maxScore {
					maxScore = s.Score
					maxSeverity = s.Severity
				}
			}

			rules = append(rules, Rule{
				ID:   exposure,
				Name: exposure,
				ShortDescription: Message{
					Text: fmt.Sprintf("Vulnerability %s", exposure),
				},
				FullDescription: Message{
					Text: fmt.Sprintf("Vulnerability %s found in image %s", exposure, result.Image),
				},
				HelpURI: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", exposure),
				DefaultConfig: DefaultConfig{
					Level: mapSeverityToLevel(maxSeverity),
				},
			})
		}

		// Create a result for each source reporting this exposure
		for _, source := range sources {
			r := Result{
				RuleID:    exposure,
				RuleIndex: ruleIndex[exposure],
				Level:     mapSeverityToLevel(source.Severity),
				Message: Message{
					Text: fmt.Sprintf(
						"%s vulnerability %s (severity: %s, score: %.1f, source: %s)",
						capitalizeFirst(source.Severity),
						exposure,
						source.Severity,
						source.Score,
						source.Source,
					),
				},
				Locations: []Location{
					{
						LogicalLocations: []LogicalLocation{
							{
								Name:               result.Image,
								FullyQualifiedName: fmt.Sprintf("%s@%s", result.Image, result.Digest),
								Kind:               "container-image",
							},
						},
					},
				},
			}
			results = append(results, r)
		}
	}

	return &Report{
		Schema:  SchemaURI,
		Version: Version,
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           tool,
						Version:        version,
						InformationURI: "https://github.com/mchmarny/vimp",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

// formatResultMessage creates a human-readable message for a vulnerability.
func formatResultMessage(v *data.ImageVulnerability) string {
	fixed := "no fix available"
	if v.IsFixed {
		fixed = "fix available"
	}

	severity := v.Severity
	if len(severity) > 0 {
		severity = strings.ToUpper(severity[:1]) + severity[1:]
	}

	return fmt.Sprintf(
		"%s vulnerability %s found in %s@%s (severity: %s, score: %.1f, %s, source: %s)",
		severity,
		v.Exposure,
		v.Package,
		v.Version,
		v.Severity,
		v.Score,
		fixed,
		v.Source,
	)
}
