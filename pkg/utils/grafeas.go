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

func toCVSSv3AttackVector(v string) g.CVSSv3_AttackVector {
	switch v {
	case "N":
		return g.CVSSv3_ATTACK_VECTOR_NETWORK
	case "A":
		return g.CVSSv3_ATTACK_VECTOR_ADJACENT
	case "L":
		return g.CVSSv3_ATTACK_VECTOR_LOCAL
	case "P":
		return g.CVSSv3_ATTACK_VECTOR_PHYSICAL
	}
	return g.CVSSv3_ATTACK_VECTOR_UNSPECIFIED
}

func toCVSSv3AttackComplexity(v string) g.CVSSv3_AttackComplexity {
	switch v {
	case "L":
		return g.CVSSv3_ATTACK_COMPLEXITY_LOW
	case "H":
		return g.CVSSv3_ATTACK_COMPLEXITY_HIGH
	}
	return g.CVSSv3_ATTACK_COMPLEXITY_UNSPECIFIED
}

func toCVSSv3PrivilegesRequired(v string) g.CVSSv3_PrivilegesRequired {
	switch v {
	case "L":
		return g.CVSSv3_PRIVILEGES_REQUIRED_LOW
	case "H":
		return g.CVSSv3_PRIVILEGES_REQUIRED_HIGH
	case "N":
		return g.CVSSv3_PRIVILEGES_REQUIRED_NONE
	}
	return g.CVSSv3_PRIVILEGES_REQUIRED_UNSPECIFIED
}

func toCVSSv3UserInteraction(v string) g.CVSSv3_UserInteraction {
	switch v {
	case "N":
		return g.CVSSv3_USER_INTERACTION_NONE
	case "R":
		return g.CVSSv3_USER_INTERACTION_REQUIRED
	}
	return g.CVSSv3_USER_INTERACTION_UNSPECIFIED
}

func toCVSSv3S(v string) g.CVSSv3_Scope {
	switch v {
	case "U":
		return g.CVSSv3_SCOPE_UNCHANGED
	case "C":
		return g.CVSSv3_SCOPE_CHANGED
	}
	return g.CVSSv3_SCOPE_UNSPECIFIED
}

func toCVSSv3Impact(v string) g.CVSSv3_Impact {
	switch v {
	case "H":
		return g.CVSSv3_IMPACT_HIGH
	case "L":
		return g.CVSSv3_IMPACT_LOW
	case "N":
		return g.CVSSv3_IMPACT_NONE
	}
	return g.CVSSv3_IMPACT_UNSPECIFIED
}

func ToCVSSv3(baseScore float32, vector string) *g.CVSSv3 {
	c := g.CVSSv3{
		BaseScore: baseScore,
	}

	for _, v := range strings.Split(vector, "/") {
		tokens := strings.Split(v, ":")
		if len(tokens) != 2 {
			continue
		}

		switch tokens[0] {
		case "AV":
			c.AttackVector = toCVSSv3AttackVector(tokens[1])
		case "AC":
			c.AttackComplexity = toCVSSv3AttackComplexity(tokens[1])
		case "PR":
			c.PrivilegesRequired = toCVSSv3PrivilegesRequired(tokens[1])
		case "UI":
			c.UserInteraction = toCVSSv3UserInteraction(tokens[1])
		case "S":
			c.Scope = toCVSSv3S(tokens[1])
		case "C":
			c.ConfidentialityImpact = toCVSSv3Impact(tokens[1])
		case "I":
			c.IntegrityImpact = toCVSSv3Impact(tokens[1])
		case "A":
			c.AvailabilityImpact = toCVSSv3Impact(tokens[1])
		}
	}

	return &c
}
