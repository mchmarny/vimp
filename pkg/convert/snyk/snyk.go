package snyk

import (
	"context"
	"fmt"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	g "google.golang.org/genproto/googleapis/grafeas/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Convert(ctx context.Context, s *src.Source) (map[string]types.NoteOccurrences, error) {
	if s == nil || s.Data == nil {
		return nil, errors.New("valid source required")
	}

	if !s.Data.Search("vulnerabilities").Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make(map[string]types.NoteOccurrences, 0)

	for _, v := range s.Data.Search("vulnerabilities").Children() {
		cve := v.Search("identifiers", "CVE").Index(0).Data().(string)

		// create note
		n := convertNote(s, v)

		// don't add notes with no CVSS score
		if n.GetVulnerability().CvssScore == 0 {
			continue
		}

		// If cve is not found, add to map
		if _, ok := list[cve]; !ok {
			list[cve] = types.NoteOccurrences{Note: n}
		}
		nocc := list[cve]
		occ := convertOccurrence(s, v)
		nocc.Occurrences = append(nocc.Occurrences, occ)
		list[cve] = nocc
	}

	for cve, v := range list {
		log.Debug().Msgf("CVE %s: Instances (%d)", cve, len(v.Occurrences))
	}

	return list, nil
}

func convertOccurrence(s *src.Source, v *gabs.Container) *g.Occurrence {
	o := g.Occurrence{
		ResourceUri: s.URI,
		NoteName:    "",
		Details: &g.Occurrence_Vulnerability{
			Vulnerability: &g.VulnerabilityOccurrence{
				CvssScore: toFloat32(v.Search("cvssScore").Data()),
				PackageIssue: []*g.VulnerabilityOccurrence_PackageIssue{{
					AffectedCpeUri:  makeCPE(v),
					AffectedPackage: v.Search("packageName").Data().(string),
					AffectedVersion: &g.Version{
						Name: v.Search("version").Data().(string),
						Kind: g.Version_MINIMUM,
					},
					FixedCpeUri:  makeCPE(v),                              // TODO: This is same as affected
					FixedPackage: v.Search("packageName").Data().(string), // TODO: This is same as affected
					FixedVersion: &g.Version{
						Name: v.Search("version").Data().(string), // TODO: This is same as affected
						Kind: g.Version_MINIMUM,
					},
				}},
			}},
	}
	return &o
}

func convertNote(s *src.Source, v *gabs.Container) *g.Note {
	// create note
	n := g.Note{
		Name:             v.Search("identifiers", "CVE").Index(0).Data().(string),
		ShortDescription: v.Search("title").Data().(string),
		LongDescription:  toString(v.Search("CVSSv3").Data()),
		RelatedUrl: []*g.RelatedUrl{
			{
				Label: "Registry",
				Url:   s.URI,
			},
		},
		CreateTime: toTime(v.Search("creationTime").Data().(string)),
		UpdateTime: toTime(v.Search("modificationTime").Data().(string)),
		Type: &g.Note_Vulnerability{
			Vulnerability: &g.VulnerabilityNote{
				CvssScore: toFloat32(v.Search("cvssScore").Data()),
				CvssV3: &g.CVSSv3{
					BaseScore: toFloat32(v.Search("cvssScore").Data()),
				},
				Details: []*g.VulnerabilityNote_Detail{
					{
						AffectedCpeUri:  makeCPE(v),
						AffectedPackage: v.Search("packageName").Data().(string),
						AffectedVersionStart: &g.Version{
							Name:      v.Search("version").Data().(string),
							Inclusive: true,
							Kind:      g.Version_MINIMUM,
						},
						Description:      v.Search("name").Data().(string),
						SeverityName:     v.Search("severity").Data().(string),
						Source:           v.Search("id").Data().(string),
						SourceUpdateTime: toTime(v.Search("disclosureTime").Data().(string)),
						Vendor:           v.Search("packageManager").Data().(string),
					},
				},
				//TODO: Severity: toSeverity(v.Search("severity").Data().(string)),
				Severity: g.Severity_CRITICAL,
			},
		},
	} // end note

	// References
	for _, r := range v.Search("references").Children() {
		n.RelatedUrl = append(n.RelatedUrl, &g.RelatedUrl{
			Url:   r.Search("url").Data().(string),
			Label: r.Search("title").Data().(string),
		})
	}

	return &n
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

func toFloat32(v interface{}) float32 {
	if v == nil {
		return 0
	}

	switch v := v.(type) {
	case float32:
		return v
	case float64: // TODO: handle overflow
		return float32(v)
	case int:
		return float32(v)
	case int32:
		return float32(v)
	case int64:
		return float32(v)
	case uint:
		return float32(v)
	case uint32:
		return float32(v)
	case uint64:
		return float32(v)
	}
	return 0
}

func toTime(v string) *timestamppb.Timestamp {
	t, _ := time.Parse("2006-01-02T15:04:05.999999Z", v)
	return timestamppb.New(t)
}
