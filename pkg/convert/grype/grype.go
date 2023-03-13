package grype

import (
	"context"
	"strings"

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
		// create note
		n := convertNote(s, v)

		// don't add notes with no CVSS score
		if n == nil || n.GetVulnerability().CvssScore == 0 {
			continue
		}
		cve := n.Name

		// If cve is not found, add to map
		if _, ok := list[cve]; !ok {
			list[cve] = types.NoteOccurrences{Note: n}
		}
		nocc := list[cve]
		occ := convertOccurrence(s, v, n.Name)
		if occ != nil {
			nocc.Occurrences = append(nocc.Occurrences, occ)
		}
		list[cve] = nocc
	}

	return list, nil
}

func convertOccurrence(s *src.Source, v *gabs.Container, noteName string) *g.Occurrence {
	// nvd vulnerability
	rvList := v.Search("relatedVulnerabilities").Children()
	var rv *gabs.Container
	for _, rvNode := range rvList {
		if rvNode.Search("namespace").Data().(string) == "nvd:cpe" {
			rv = rvNode
			break
		}
	}
	if rv == nil {
		return nil
	}
	cve := rv.Search("id").Data().(string)

	// cvssv2
	cvssList := rv.Search("cvss").Children()
	var cvss2, cvss3 *gabs.Container
	for _, cvss := range cvssList {
		switch cvss.Search("version").Data().(string) {
		case "2.0":
			cvss2 = cvss
		case "3.0", "3.1":
			cvss3 = cvss
		}
	}
	if cvss2 == nil {
		return nil
	}

	// Create Occurrence
	o := g.Occurrence{
		ResourceUri: s.URI,
		NoteName:    noteName,
		Details: &g.Occurrence_Vulnerability{
			Vulnerability: &g.VulnerabilityOccurrence{
				ShortDescription: cve,
				LongDescription:  rv.Search("description").Data().(string),
				RelatedUrls: []*g.RelatedUrl{
					{
						Label: "Registry",
						Url:   s.URI,
					},
				},
				CvssVersion: g.CVSSVersion_CVSS_VERSION_2,
				CvssScore:   utils.ToFloat32(cvss2.Search("metrics", "baseScore").Data()),
				Severity:    utils.ToGrafeasSeverity(rv.Search("severity").Data().(string)),
				// TODO: What is the difference between severity and effective severity?
				EffectiveSeverity: utils.ToGrafeasSeverity(rv.Search("severity").Data().(string)),
			}},
	}

	// PackageIssues
	if len(v.Search("vulnerability", "fix", "versions").Children()) == 0 {
		o.GetVulnerability().PackageIssue = append(
			o.GetVulnerability().PackageIssue,
			getBasePackageIssue(v))
	} else {
		for _, version := range v.Search("vulnerability", "fix", "versions").Children() {
			pi := getBasePackageIssue(v)
			pi.FixedVersion = &g.Version{
				Name: version.Data().(string),
				Kind: g.Version_NORMAL,
			}
			o.GetVulnerability().PackageIssue = append(o.GetVulnerability().PackageIssue, pi)
		}
	}

	// CVSSv3
	if cvss3 != nil {
		o.GetVulnerability().Cvssv3 = utils.ToCVSS(
			utils.ToFloat32(cvss3.Search("metrics", "baseScore").Data()),
			cvss3.Search("vector").Data().(string),
		)
	}

	// References
	for _, r := range rv.Search("urls").Children() {
		o.GetVulnerability().RelatedUrls = append(o.GetVulnerability().RelatedUrls, &g.RelatedUrl{
			Url:   r.Data().(string),
			Label: "Url",
		})
	}
	return &o
}

func convertNote(s *src.Source, v *gabs.Container) *g.Note {
	// nvd vulnerability
	rvList := v.Search("relatedVulnerabilities").Children()
	var rv *gabs.Container
	for _, rvNode := range rvList {
		if rvNode.Search("namespace").Data().(string) == "nvd:cpe" {
			rv = rvNode
			break
		}
	}
	if rv == nil {
		return nil
	}
	cve := rv.Search("id").Data().(string)

	// cvssv2
	cvssList := rv.Search("cvss").Children()
	var cvss2, cvss3 *gabs.Container
	for _, cvss := range cvssList {
		switch cvss.Search("version").Data().(string) {
		case "2.0":
			cvss2 = cvss
		case "3.0", "3.1":
			cvss3 = cvss
		}
	}
	if cvss2 == nil {
		return nil
	}

	// create note
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
				CvssVersion: g.CVSSVersion_CVSS_VERSION_2,
				CvssScore:   utils.ToFloat32(cvss2.Search("metrics", "baseScore").Data()),
				// Details in Notes are not populated since we will never see the full list
				Details: []*g.VulnerabilityNote_Detail{
					{
						AffectedCpeUri:  "N/A",
						AffectedPackage: "N/A",
					},
				},
				Severity: utils.ToGrafeasSeverity(rv.Search("severity").Data().(string)),
			},
		},
	} // end note

	// CVSSv3
	if cvss3 != nil {
		n.GetVulnerability().CvssV3 = utils.ToCVSSv3(
			utils.ToFloat32(cvss3.Search("metrics", "baseScore").Data()),
			cvss3.Search("vector").Data().(string),
		)
	}

	// References
	for _, r := range rv.Search("urls").Children() {
		n.RelatedUrl = append(n.RelatedUrl, &g.RelatedUrl{
			Url:   r.Data().(string),
			Label: "Url",
		})
	}

	return &n
}

func getBasePackageIssue(v *gabs.Container) *g.VulnerabilityOccurrence_PackageIssue {
	return &g.VulnerabilityOccurrence_PackageIssue{
		PackageType:     strings.ToUpper(v.Search("artifact", "language").Data().(string)),
		AffectedCpeUri:  v.Search("artifact", "cpes").Index(0).Data().(string),
		AffectedPackage: v.Search("artifact", "name").Data().(string),
		AffectedVersion: &g.Version{
			Name: v.Search("artifact", "version").Data().(string),
			Kind: g.Version_NORMAL,
		},
		FixedCpeUri:  v.Search("artifact", "cpes").Index(0).Data().(string),
		FixedPackage: v.Search("artifact", "name").Data().(string),
		FixedVersion: &g.Version{
			Kind: g.Version_MAXIMUM,
		},
	}
}
