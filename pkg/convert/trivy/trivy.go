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

// Convert converts Trivy JSON to Grafeas Note/Occurrence format.
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
			n := convertNote(s, v, cve)

			// don't add notes with no CVSS score
			if n == nil || n.GetVulnerability().CvssScore == 0 {
				continue
			}

			// If cve is not found, add to map
			if _, ok := list[cve]; !ok {
				list[cve] = types.NoteOccurrences{Note: n}
			}
			nocc := list[cve]
			occ := convertOccurrence(s, v, cve, n.Name)
			nocc.Occurrences = append(nocc.Occurrences, occ)
			list[cve] = nocc
		}
	}

	return list, nil
}

func convertNote(s *src.Source, v *gabs.Container, cve string) *g.Note {
	if v.Search("CVSS", "nvd").Data() == nil {
		return nil
	}
	nvd := v.Search("CVSS", "nvd")

	n := g.Note{
		Name:             cve,
		ShortDescription: cve,
		RelatedUrl: []*g.RelatedUrl{
			{
				Label: "Registry",
				Url:   s.URI,
			},
			{
				Label: "PrimaryURL",
				Url:   v.Search("PrimaryURL").Data().(string),
			},
		},
		Type: &g.Note_Vulnerability{
			Vulnerability: &g.VulnerabilityNote{
				// Details in Notes are not populated since we will never see the full list
				Details: []*g.VulnerabilityNote_Detail{
					{
						AffectedCpeUri:  "N/A",
						AffectedPackage: "N/A",
					},
				},
				Severity:         utils.ToGrafeasSeverity(v.Search("Severity").Data().(string)),
				SourceUpdateTime: utils.ToGRPCTime(v.Search("LastModifiedDate").Data()),
			},
		},
	} // end note

	// CVSSv2
	if nvd.Search("V2Vector").Data() != nil {
		n.LongDescription = nvd.Search("V2Vector").Data().(string)
		n.GetVulnerability().CvssVersion = g.CVSSVersion_CVSS_VERSION_2
		n.GetVulnerability().CvssScore = utils.ToFloat32(nvd.Search("V2Score").Data())
	}

	// CVSSv3, will override v2 values
	if nvd.Search("V3Vector").Data() != nil {
		n.LongDescription = nvd.Search("V3Vector").Data().(string)
		n.GetVulnerability().CvssVersion = g.CVSSVersion_CVSS_VERSION_3
		n.GetVulnerability().CvssScore = utils.ToFloat32(nvd.Search("V3Score").Data())
		n.GetVulnerability().CvssV3 = utils.ToCVSSv3(
			utils.ToFloat32(nvd.Search("V3Score").Data()),
			nvd.Search("V3Vector").Data().(string),
		)
	}

	// References
	for _, r := range v.Search("References").Children() {
		n.RelatedUrl = append(n.RelatedUrl, &g.RelatedUrl{
			Url:   r.Data().(string),
			Label: "Url",
		})
	}

	return &n
}

func convertOccurrence(s *src.Source, v *gabs.Container, cve string, noteName string) *g.Occurrence {
	if v.Search("CVSS", "nvd").Data() == nil {
		return nil
	}
	nvd := v.Search("CVSS", "nvd")

	// Create Occurrence
	o := g.Occurrence{
		ResourceUri: s.URI,
		NoteName:    noteName,
		Details: &g.Occurrence_Vulnerability{
			Vulnerability: &g.VulnerabilityOccurrence{
				ShortDescription: cve,
				RelatedUrls: []*g.RelatedUrl{
					{
						Label: "Registry",
						Url:   s.URI,
					},
					{
						Label: "PrimaryURL",
						Url:   v.Search("PrimaryURL").Data().(string),
					},
				},
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
				Severity: utils.ToGrafeasSeverity(v.Search("Severity").Data().(string)),
				// TODO: What is the difference between severity and effective severity?
				EffectiveSeverity: utils.ToGrafeasSeverity(v.Search("Severity").Data().(string)),
			}},
	}

	// CVSSv2
	if nvd.Search("V2Vector").Data() != nil {
		o.GetVulnerability().LongDescription = nvd.Search("V2Vector").Data().(string)
		o.GetVulnerability().CvssVersion = g.CVSSVersion_CVSS_VERSION_2
		o.GetVulnerability().CvssScore = utils.ToFloat32(nvd.Search("V2Score").Data())
	}

	// CVSSv3, will override v2 values
	if nvd.Search("V3Vector").Data() != nil {
		o.GetVulnerability().LongDescription = nvd.Search("V3Vector").Data().(string)
		o.GetVulnerability().CvssVersion = g.CVSSVersion_CVSS_VERSION_3
		o.GetVulnerability().CvssScore = utils.ToFloat32(nvd.Search("V3Score").Data())
		o.GetVulnerability().Cvssv3 = utils.ToCVSS(
			utils.ToFloat32(nvd.Search("V3Score").Data()),
			nvd.Search("V3Vector").Data().(string),
		)
	}

	// References
	for _, r := range v.Search("References").Children() {
		o.GetVulnerability().RelatedUrls = append(o.GetVulnerability().RelatedUrls, &g.RelatedUrl{
			Url:   r.Data().(string),
			Label: "Url",
		})
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
