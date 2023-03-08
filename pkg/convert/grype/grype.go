package grype

import (
	"context"

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

	if !s.Data.Search("matches").Exists() {
		return nil, errors.New("unable to find vulnerabilities in source data")
	}

	list := make(map[string]types.NoteOccurrences, 0)

	for _, v := range s.Data.Search("matches").Children() {
		cve := v.Search("vulnerability", "id").Data().(string)

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
		if occ != nil {
			nocc.Occurrences = append(nocc.Occurrences, occ)
		}
		list[cve] = nocc
	}

	return list, nil
}

func convertOccurrence(s *src.Source, v *gabs.Container) *g.Occurrence {
	// relatedVulnerabilities
	rvList := v.Search("relatedVulnerabilities").Children()
	if len(rvList) == 0 {
		return nil
	}
	rv := rvList[0]

	// match
	matchList := v.Search("matchDetails").Children()
	if len(matchList) == 0 {
		return nil
	}
	match := matchList[0] // TODO: Create a detail per match

	// cvss
	cvssList := rv.Search("cvss").Children()
	var cvss2 *gabs.Container
	for _, cvss := range cvssList {
		if cvss.Search("version").Data().(string) == "2.0" {
			cvss2 = cvss
		}
	}
	if cvss2 == nil {
		return nil
	}

	o := g.Occurrence{
		ResourceUri: s.URI,
		NoteName:    "",
		Details: &g.Occurrence_Vulnerability{
			Vulnerability: &g.VulnerabilityOccurrence{
				CvssScore: utils.ToFloat32(cvss2.Search("metrics", "baseScore").Data()),
				PackageIssue: []*g.VulnerabilityOccurrence_PackageIssue{{
					AffectedCpeUri:  v.Search("artifact", "cpes").Index(0).Data().(string),
					AffectedPackage: match.Search("searchedBy", "package", "version").String(), // TODO: Need to handle case where a node in the chain is nil. Use Data().(string) instead
					AffectedVersion: &g.Version{
						Name: match.Search("searchedBy", "package", "version").String(),
						Kind: g.Version_MINIMUM,
					},
					FixedCpeUri:  v.Search("artifact", "cpes").Index(0).Data().(string),     // TODO: This is same as affected
					FixedPackage: match.Search("searchedBy", "package", "version").String(), // TODO: This is same as affected
					FixedVersion: &g.Version{
						Name: match.Search("searchedBy", "package", "version").String(), // TODO: This is same as affected
						Kind: g.Version_MINIMUM,
					},
				}},
			}},
	}
	return &o
}

func convertNote(s *src.Source, v *gabs.Container) *g.Note {
	// create note

	// relatedVulnerabilities
	rvList := v.Search("relatedVulnerabilities").Children()
	if len(rvList) == 0 {
		return nil
	}
	rv := rvList[0]
	cve := rv.Search("id").Data().(string)

	// match
	matchList := v.Search("matchDetails").Children()
	if len(matchList) == 0 {
		return nil
	}
	match := matchList[0] // TODO: Create a detail per match

	// cvss
	cvssList := rv.Search("cvss").Children()
	var cvss2 *gabs.Container
	for _, cvss := range cvssList {
		if cvss.Search("version").Data().(string) == "2.0" {
			cvss2 = cvss
		}
	}
	if cvss2 == nil {
		return nil
	}

	n := g.Note{
		Name:             cve,
		ShortDescription: cve,
		LongDescription:  rv.Search("description").Data().(string),
		RelatedUrl: []*g.RelatedUrl{
			{
				Label: "Registry",
				Url:   s.URI,
			},
		},
		Type: &g.Note_Vulnerability{
			Vulnerability: &g.VulnerabilityNote{
				CvssScore: utils.ToFloat32(cvss2.Search("metrics", "baseScore").Data()),
				CvssV3: &g.CVSSv3{
					BaseScore: utils.ToFloat32(cvss2.Search("metrics", "baseScore").Data()),
				},
				Details: []*g.VulnerabilityNote_Detail{
					{
						AffectedCpeUri:  v.Search("artifact", "cpes").Index(0).Data().(string), // TODO: How do we show a list of CPEs?
						AffectedPackage: match.Search("searchedBy", "package", "name").String(),
						AffectedVersionStart: &g.Version{
							Name:      match.Search("searchedBy", "package", "version").String(),
							Inclusive: true,
							Kind:      g.Version_MINIMUM,
						},
						Description:  rv.Search("description").Data().(string),
						SeverityName: rv.Search("severity").Data().(string),
						Source:       rv.Search("namespace").Data().(string),
						Vendor:       match.Search("searchedBy", "distro", "type").String(),
					},
				},
				Severity: utils.ToGrafeasSeverity(rv.Search("severity").Data().(string)),
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
