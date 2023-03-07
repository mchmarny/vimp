package snyk

import (
	"context"
	"fmt"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vulctl/pkg/ca"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	aa "google.golang.org/api/containeranalysis/v1"
)

func Convert(ctx context.Context, s *src.Source, t *ca.Client) error {
	if s == nil || s.Data == nil {
		return errors.New("valid source required")
	}

	if !s.Data.Search("vulnerabilities").Exists() {
		return errors.New("unable to find vulnerabilities in source data")
	}

	for _, v := range s.Data.Search("vulnerabilities").Children() {
		if !v.Search("identifiers", "CVE").Exists() {
			continue
		}

		cve := v.Search("identifiers", "CVE").Index(0).Data().(string)
		n := makeNote(v)

		id, err := t.CreateNote(n, cve)
		if err != nil {
			return errors.Wrap(err, "error creating note")
		}

		o := makeOccurrence(v, *id, s.URI)
		if err := t.CreateOccurrence(o, *id); err != nil {
			return errors.Wrap(err, "error creating occurrence")
		}

		log.Info().Msgf("note and occurrence created: %s - %s", *id, s.URI)
	}

	return nil
}

func makeNote(v *gabs.Container) *aa.Note {
	n := &aa.Note{
		Kind:             "VULNERABILITY",
		Name:             v.Search("title").Data().(string),
		ShortDescription: v.Search("identifiers", "CVE").Index(0).Data().(string),
		Vulnerability: &aa.VulnerabilityNote{
			Severity:  toSeverity(v.Search("severity").Data().(string)),
			CvssScore: toFloat(v.Search("cvssScore").Data()),
			Details: []*aa.Detail{
				{
					AffectedPackage: v.Search("packageName").Data().(string),
					AffectedCpeUri:  makeCPE(v),
					AffectedVersionStart: &aa.Version{
						Name:      v.Search("version").Data().(string),
						Inclusive: true,
						Kind:      "MINIMUM",
					},
					AffectedVersionEnd: &aa.Version{
						Name:      v.Search("version").Data().(string),
						Inclusive: true,
						Kind:      "MAXIMUM",
					},
					FixedPackage: v.Search("packageName").Data().(string),
					Description:  v.Search("name").Data().(string),
				},
			},
		},
	} // end note

	// references
	for _, r := range v.Search("references").Children() {
		n.RelatedUrl = append(n.RelatedUrl, &aa.RelatedUrl{
			Url:   r.Search("url").Data().(string),
			Label: r.Search("title").Data().(string),
		})
	}
	return n
}

func makeOccurrence(v *gabs.Container, noteName, imageURI string) *aa.Occurrence {
	o := &aa.Occurrence{
		Kind:        "VULNERABILITY",
		NoteName:    noteName,
		ResourceUri: imageURI,
		Vulnerability: &aa.VulnerabilityOccurrence{
			CvssScore: toFloat(v.Search("cvssScore").Data()),
			Severity:  toSeverity(v.Search("severity").Data().(string)),
			PackageIssue: []*aa.PackageIssue{
				{
					AffectedCpeUri:  makeCPE(v),
					AffectedPackage: v.Search("packageName").Data().(string),
					AffectedVersion: &aa.Version{
						Name:      v.Search("version").Data().(string),
						Inclusive: true,
						Kind:      "MINIMUM",
					},
					FixedCpeUri:  makeCPE(v),
					FixedPackage: v.Search("packageName").Data().(string),
					FixedVersion: &aa.Version{
						Name:      v.Search("version").Data().(string),
						Inclusive: true,
						Kind:      "MINIMUM",
					},
				},
			},
		},
	} // end note

	// CVSS
	if v.Search("CVSSv3").Exists() {
		// CVSSv3 errs with .(string)
		vec := toString(v.Search("CVSSv3").Data())
		o.Vulnerability.Cvssv3 = &aa.CVSS{
			AttackComplexity:      getAttackComplexity(vec),
			AttackVector:          getAttackVector(vec),
			AvailabilityImpact:    getAvailabilityImpact(vec),
			ConfidentialityImpact: getConfidentialityImpact(vec),
			IntegrityImpact:       getIntegrityImpact(vec),
			PrivilegesRequired:    getPrivilegesRequired(vec),
			Scope:                 getScope(vec),
			UserInteraction:       getUserInteraction(vec),
		}
	}

	return o
}

// makeCPE creates CPE from Snyk data as the OSS CLI does not generate CPEs
// NOTE: This is for demo purposes only and is not a complete CPE generator
// Ref: https://en.wikipedia.org/wiki/Common_Platform_Enumeration
// Schema: cpe:2.3:a:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
func makeCPE(v *gabs.Container) string {
	pkgName := v.Search("name").Data().(string)
	pkgVersion := v.Search("version").Data().(string)

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
		pkgName,
		pkgName,
		pkgVersion)
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
