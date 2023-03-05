package snyk

import (
	"context"
	"fmt"
	"strings"

	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/pkg/errors"
	aa "google.golang.org/api/containeranalysis/v1"
)

func Convert(ctx context.Context, s *src.Source) ([]*aa.Note, error) {
	if s == nil || s.Data == nil {
		return nil, errors.New("valid source required")
	}

	if !s.Data.Search("vulnerabilities").Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make([]*aa.Note, 0)

	for _, v := range s.Data.Search("vulnerabilities").Children() {
		n := &aa.Note{
			Kind:             "VULNERABILITY",
			Name:             v.Search("identifiers", "CVE").Index(0).Data().(string),
			ShortDescription: v.Search("title").Data().(string),
			LongDescription:  v.Search("description").Data().(string),
			RelatedUrl: []*aa.RelatedUrl{
				{
					Label: "Registry",
					Url:   s.URI,
				},
			},
			CreateTime: v.Search("creationTime").Data().(string),
			UpdateTime: v.Search("modificationTime").Data().(string),
			Vulnerability: &aa.VulnerabilityNote{
				CvssScore: toFloat(v.Search("cvssScore").Data()),
				CvssV3: &aa.CVSSv3{
					BaseScore: toFloat(v.Search("cvssScore").Data()),
				},
				Details: []*aa.Detail{
					{
						// AffectedCpeUri:  v.Search("identifiers", "cpes").Index(0).Data().(string),
						AffectedPackage: v.Search("packageName").Data().(string),
						AffectedVersionStart: &aa.Version{
							Name:      v.Search("version").Data().(string),
							Inclusive: true,
							Kind:      "MINIMUM",
						},
						Description:      v.Search("name").Data().(string),
						SeverityName:     v.Search("severity").Data().(string),
						Source:           "NVD",
						SourceUpdateTime: v.Search("disclosureTime").Data().(string),
						Vendor:           v.Search("packageManager").Data().(string),
					},
				},
				Severity: toSeverity(v.Search("severity").Data().(string)),
			},
		} // end note

		// CVSS
		if v.Search("CVSSv3").Exists() {
			// CVSSv3 errs with .(string)
			vec := toString(v.Search("CVSSv3").Data())
			n.Vulnerability.CvssV3.AttackComplexity = getAttackComplexity(vec)
			n.Vulnerability.CvssV3.AttackVector = getAttackVector(vec)
			n.Vulnerability.CvssV3.AvailabilityImpact = getAvailabilityImpact(vec)
			n.Vulnerability.CvssV3.ConfidentialityImpact = getConfidentialityImpact(vec)
			n.Vulnerability.CvssV3.IntegrityImpact = getIntegrityImpact(vec)
			n.Vulnerability.CvssV3.PrivilegesRequired = getPrivilegesRequired(vec)
			n.Vulnerability.CvssV3.Scope = getScope(vec)
			n.Vulnerability.CvssV3.UserInteraction = getUserInteraction(vec)
		}

		// References
		for _, r := range v.Search("references").Children() {
			n.RelatedUrl = append(n.RelatedUrl, &aa.RelatedUrl{
				Url:   r.Search("url").Data().(string),
				Label: r.Search("title").Data().(string),
			})
		}

		// don't add notes with no CVSS score
		if n.Vulnerability.CvssScore == 0 {
			continue
		}

		list = append(list, n)
	}

	return list, nil
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}

	s, ok := v.(string)
	if ok {
		return s
	}

	return fmt.Sprintf("%v", v)
}

func toFloat(v interface{}) float64 {
	if v == nil {
		return 0
	}

	switch v := v.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case uint:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	}
	return 0
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
