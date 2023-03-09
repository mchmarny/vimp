package snyk

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

	if !s.Data.Search("vulnerabilities").Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make(map[string]types.NoteOccurrences, 0)

	for _, v := range s.Data.Search("vulnerabilities").Children() {
		cve := v.Search("identifiers", "CVE").Index(0).Data().(string)

		// create note
		n := convertNote(s, v)

		// don't add notes with no CVSS score
		if n == nil || n.GetVulnerability().CvssScore == 0 {
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

	return list, nil
}

func convertNote(s *src.Source, v *gabs.Container) *g.Note {
	cve := v.Search("identifiers", "CVE").Index(0).Data().(string)

	// Get cvss3 details from NVD
	var cvss3 *gabs.Container
	for _, detail := range v.Search("cvssDetails").Children() {
		if utils.ToString(detail.Search("assigner").Data()) == "NVD" {
			cvss3 = detail
		}
	}
	if cvss3 == nil {
		return nil
	}

	// create note
	n := g.Note{
		Name:             cve,
		ShortDescription: cve,
		LongDescription:  utils.ToString(v.Search("CVSSv3").Data()),
		RelatedUrl: []*g.RelatedUrl{
			{
				Label: "Registry",
				Url:   s.URI,
			},
		},
		Type: &g.Note_Vulnerability{
			Vulnerability: &g.VulnerabilityNote{
				CvssVersion: g.CVSSVersion_CVSS_VERSION_3,
				CvssScore:   utils.ToFloat32(cvss3.Search("cvssV3BaseScore").Data()),
				CvssV3: utils.ToCVSSv3(
					utils.ToFloat32(cvss3.Search("cvssV3BaseScore").Data()),
					cvss3.Search("cvssV3Vector").Data().(string),
				),
				// Details in Notes are not populated since we will never see the full list
				Details: []*g.VulnerabilityNote_Detail{
					{
						AffectedCpeUri:  "N/A",
						AffectedPackage: "N/A",
					},
				},
				Severity:         utils.ToGrafeasSeverity(v.Search("nvdSeverity").Data().(string)),
				SourceUpdateTime: utils.ToGRPCTime(cvss3.Search("modificationTime").Data()),
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

func convertOccurrence(s *src.Source, v *gabs.Container) *g.Occurrence {
	o := g.Occurrence{
		ResourceUri: s.URI,
		NoteName:    "",
		Details: &g.Occurrence_Vulnerability{
			Vulnerability: &g.VulnerabilityOccurrence{
				CvssScore: utils.ToFloat32(v.Search("cvssScore").Data()),
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
