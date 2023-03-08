package trivy

import (
	"context"
	"fmt"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vulctl/pkg/src"
	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/mchmarny/vulctl/pkg/utils"
	"github.com/pkg/errors"
	g "google.golang.org/genproto/googleapis/grafeas/v1"
)

// Convert converts Snyk JSON to Grafeas Note/Occurrence format.
func Convert(ctx context.Context, s *src.Source) (map[string]types.NoteOccurrences, error) {
	if s == nil || s.Data == nil {
		return nil, errors.New("valid source required")
	}

	if !s.Data.Search("Results").Exists() {
		return nil, errors.New("unable to find Results in source data")
	}

	list := make(map[string]types.NoteOccurrences, 0)

	for _, r := range s.Data.Search("Results").Children() {
		for _, v := range r.Search("Vulnerabilities").Children() {
			cve := v.Search("VulnerabilityID").Data().(string)

			// create note
			n := convertNote(v, cve)

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
	}

	return list, nil
}

func convertNote(v *gabs.Container, cve string) *g.Note {
	n := g.Note{
		Name:             cve,
		ShortDescription: v.Search("Title").Data().(string),
		LongDescription:  utils.ToString(v.Search("CVSS", "nvd", "V3Vector").Data()),
		RelatedUrl: []*g.RelatedUrl{
			{
				Label: "PrimaryURL",
				Url:   v.Search("PrimaryURL").Data().(string),
			},
		},
		CreateTime: utils.ToGRPCTime(v.Search("PublishedDate").Data().(string)),
		UpdateTime: utils.ToGRPCTime(v.Search("LastModifiedDate").Data().(string)),
		Type: &g.Note_Vulnerability{
			Vulnerability: &g.VulnerabilityNote{
				CvssScore: utils.ToFloat32(v.Search("CVSS", "nvd", "V2Score").Data()),
				CvssV3: &g.CVSSv3{
					BaseScore: utils.ToFloat32(v.Search("CVSS", "nvd", "V3Score").Data()),
				},
				Details: []*g.VulnerabilityNote_Detail{
					{
						AffectedCpeUri:  makeCPE(v),
						AffectedPackage: v.Search("PkgName").Data().(string),
						AffectedVersionStart: &g.Version{
							Name:      v.Search("InstalledVersion").Data().(string),
							Inclusive: true,
							Kind:      g.Version_MINIMUM,
						},
						Description:      v.Search("Description").Data().(string),
						SeverityName:     v.Search("Severity").Data().(string),
						Source:           v.Search("SeveritySource").Data().(string),
						SourceUpdateTime: utils.ToGRPCTime(v.Search("PublishedDate").Data().(string)),
						Vendor:           v.Search("SeveritySource").Data().(string),
					},
				},
				Severity: utils.ToGrafeasSeverity(v.Search("Severity").Data().(string)),
			},
		},
	} // end note

	// References
	for _, r := range v.Search("References").Children() {
		n.RelatedUrl = append(n.RelatedUrl, &g.RelatedUrl{
			Url:   r.Data().(string),
			Label: "Url",
		})
	}

	return &n
}

func convertOccurrence(s *src.Source, v *gabs.Container) *g.Occurrence {
	o := g.Occurrence{
		ResourceUri: s.URI,
		NoteName:    "",
		Details: &g.Occurrence_Vulnerability{
			Vulnerability: &g.VulnerabilityOccurrence{
				CvssScore: utils.ToFloat32(v.Search("CVSS", "nvd", "V2Score").Data()),
				PackageIssue: []*g.VulnerabilityOccurrence_PackageIssue{{
					AffectedCpeUri:  makeCPE(v),
					AffectedPackage: v.Search("PkgName").Data().(string),
					AffectedVersion: &g.Version{
						Name: v.Search("InstalledVersion").Data().(string),
						Kind: g.Version_MINIMUM,
					},
					FixedCpeUri:  makeCPE(v),                          // TODO: This is same as affected
					FixedPackage: v.Search("PkgName").Data().(string), // TODO: This is same as affected
					FixedVersion: &g.Version{
						Name: v.Search("InstalledVersion").Data().(string), // TODO: This is same as affected
						Kind: g.Version_MINIMUM,
					},
				}},
			}},
	}
	return &o
}

// makeCPE creates CPE from Snyk data as the OSS CLI does not generate CPEs
// NOTE: This is for demo purposes only and is not a complete CPE generator
// Ref: https://en.wikipedia.org/wiki/Common_Platform_Enumeration
// Schema: cpe:2.3:a:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
func makeCPE(v *gabs.Container) string {
	src := v.Search("SeveritySource").Data().(string)
	pkgName := v.Search("PkgName").Data().(string)
	pkgVersion := v.Search("InstalledVersion").Data().(string)

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
		src,
		pkgName,
		pkgVersion)
}
