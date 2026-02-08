package sarif

import (
	"fmt"
	"strings"

	"github.com/mchmarny/vimp/pkg/data"
)

const (
	SchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	Version   = "2.1.0"
)

// FromVulnerabilities converts a slice of ImageVulnerability to a SARIF report.
func FromVulnerabilities(vuls []*data.ImageVulnerability, tool, version string) *Report {
	rules := make([]Rule, 0)
	results := make([]Result, 0)
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
