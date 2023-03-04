package snyk

import (
	"context"
	"strings"

	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/pkg/errors"
	aa "google.golang.org/api/containeranalysis/v1"
)

func Convert(ctx context.Context, s *src.Source) ([]*aa.Occurrence, error) {
	if s == nil || s.Data == nil {
		return nil, errors.New("valid source required")
	}

	if !s.Data.Search("vulnerabilities").Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make([]*aa.Occurrence, 0)

	for _, v := range s.Data.Search("vulnerabilities").Children() {
		oc := &aa.Occurrence{
			Kind:        "VULNERABILITY",
			ResourceUri: s.URI,
			Vulnerability: &aa.VulnerabilityOccurrence{
				EffectiveSeverity: toSeverity(v.Search("severity").Data().(string)),
				FixAvailable:      v.Search("isPatchable").Data().(bool),
				Severity:          toSeverity(v.Search("severity").Data().(string)),
				Type:              v.Search("name").Data().(string),
				PackageIssue:      make([]*aa.PackageIssue, 0),
			},
		}

		for _, rvs := range v.Search("relatedVulnerabilities").Children() {
			for _, cvss := range rvs.Search("cvss").Children() {
				vec := cvss.Search("vector").Data().(string)
				ver := cvss.Search("version").Data().(string)
				if ver == "2.0" {
					// "AV:N/AC:L/Au:N/C:N/I:P/A:N"
					oc.Vulnerability.CvssV2 = &aa.CVSS{
						BaseScore:             cvss.Search("metrics", "baseScore").Data().(float64),
						ExploitabilityScore:   cvss.Search("metrics", "exploitabilityScore").Data().(float64),
						ImpactScore:           cvss.Search("metrics", "impactScore").Data().(float64),
						AttackComplexity:      getAttackComplexity(vec),
						AttackVector:          getAttackVector(vec),
						Authentication:        getAuthentication(vec),
						ConfidentialityImpact: getConfidentialityImpact(vec),
						IntegrityImpact:       getIntegrityImpact(vec),
						AvailabilityImpact:    getAvailabilityImpact(vec),
					}
				}
				if ver == "3.0" {
					// "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
					oc.Vulnerability.Cvssv3 = &aa.CVSS{
						BaseScore:             cvss.Search("metrics", "baseScore").Data().(float64),
						ExploitabilityScore:   cvss.Search("metrics", "exploitabilityScore").Data().(float64),
						ImpactScore:           cvss.Search("metrics", "impactScore").Data().(float64),
						AttackComplexity:      getAttackComplexity(vec),
						AttackVector:          getAttackVector(vec),
						Authentication:        getAuthentication(vec),
						ConfidentialityImpact: getConfidentialityImpact(vec),
						IntegrityImpact:       getIntegrityImpact(vec),
						AvailabilityImpact:    getAvailabilityImpact(vec),
						PrivilegesRequired:    getPrivilegesRequired(vec),
						UserInteraction:       getUserInteraction(vec),
						Scope:                 getScope(vec),
					}
				}
			}
		}

		list = append(list, oc)
	}

	return list, nil
}

// toSeverity converts grype severity to CVSS severity.
func toSeverity(v string) string {
	if v == "" {
		return "SEVERITY_UNSPECIFIED"
	}

	return strings.ToUpper(v)
}

const expectedVectorParts = 2

func getVectorPart(val, part string) string {
	// v2 - AV:N/AC:L/Au:N/C:N/I:P/A:N
	// v3 - AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N
	vectorParts := strings.Split(val, "/")
	for _, p := range vectorParts {
		kv := strings.Split(p, ":")
		if len(kv) != expectedVectorParts {
			continue
		}
		if strings.EqualFold(kv[0], part) {
			return kv[1]
		}
	}
	return ""
}

func getAttackVector(v string) string {
	switch getVectorPart(v, "AV") {
	case "N":
		return "ATTACK_VECTOR_NETWORK"
	case "A":
		return "ATTACK_VECTOR_ADJACENT"
	case "L":
		return "ATTACK_VECTOR_LOCAL"
	case "P":
		return "ATTACK_VECTOR_PHYSICAL"
	}
	return "ATTACK_VECTOR_UNSPECIFIED"
}

func getAttackComplexity(v string) string {
	switch getVectorPart(v, "AC") {
	case "L":
		return "ATTACK_COMPLEXITY_LOW"
	case "H":
		return "ATTACK_COMPLEXITY_HIGH"
	}
	return "ATTACK_COMPLEXITY_UNSPECIFIED"
}

func getAuthentication(v string) string {
	switch getVectorPart(v, "Au") {
	case "M":
		return "AUTHENTICATION_MULTIPLE"
	case "S":
		return "AUTHENTICATION_SINGLE"
	case "N":
		return "AUTHENTICATION_NONE"
	}
	return "AUTHENTICATION_UNSPECIFIED"
}

const (
	impactLevelNone        = "IMPACT_NONE"
	impactLevelLow         = "IMPACT_LOW"
	impactLevelHigh        = "IMPACT_HIGH"
	impactLevelUnspecified = "IMPACT_UNSPECIFIED"
)

func getConfidentialityImpact(v string) string {
	switch getVectorPart(v, "C") {
	case "H":
		return impactLevelHigh
	case "L":
		return impactLevelLow
	}
	return impactLevelNone
}

func getIntegrityImpact(v string) string {
	switch getVectorPart(v, "I") {
	case "H":
		return impactLevelHigh
	case "L":
		return impactLevelLow
	case "N":
		return impactLevelNone
	}
	return impactLevelUnspecified
}

func getAvailabilityImpact(v string) string {
	switch getVectorPart(v, "A") {
	case "H":
		return impactLevelHigh
	case "L":
		return impactLevelLow
	case "N":
		return impactLevelNone
	}
	return impactLevelUnspecified
}

func getPrivilegesRequired(v string) string {
	switch getVectorPart(v, "PR") {
	case "H":
		return "PRIVILEGES_REQUIRED_HIGH"
	case "L":
		return "PRIVILEGES_REQUIRED_LOW"
	case "N":
		return "PRIVILEGES_REQUIRED_NONE"
	}
	return "PRIVILEGES_REQUIRED_UNSPECIFIED"
}

func getUserInteraction(v string) string {
	switch getVectorPart(v, "UI") {
	case "R":
		return "USER_INTERACTION_REQUIRED"
	case "N":
		return "USER_INTERACTION_NONE"
	}
	return "USER_INTERACTION_UNSPECIFIED"
}

func getScope(v string) string {
	switch getVectorPart(v, "S") {
	case "C":
		return "SCOPE_CHANGED"
	case "U":
		return "SCOPE_UNCHANGED"
	}
	return "SCOPE_UNSPECIFIED"
}
