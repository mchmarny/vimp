package scanner

import (
	"fmt"
	"strings"
)

const (
	AllScans ScanType = iota
	Grype
	Snyk
	Trivy
	OSV

	allScannersStr = "all"
	grypeStr       = "grype"
	snykStr        = "snyk"
	trivyStr       = "trivy"
	osvStr         = "osv"
)

var (
	// allScanners contains scanners that support direct container image scanning.
	// OSV is excluded as it requires lockfile/SBOM scanning, not direct image scanning.
	allScanners = []ScanType{Grype, Snyk, Trivy}
)

type ScanType int64

func (s ScanType) String() string {
	switch s {
	case AllScans:
		return allScannersStr
	case Grype:
		return grypeStr
	case Snyk:
		return snykStr
	case Trivy:
		return trivyStr
	case OSV:
		return osvStr
	}
	return allScannersStr
}

// ParseScans parses the scans.
func ParseScans(s string) ([]ScanType, error) {
	if s == "" || s == allScannersStr {
		return allScanners, nil
	}

	p := strings.Split(s, ",")
	scans := make([]ScanType, 0)
	for _, v := range p {
		s, err := ParseScan(v)
		if err != nil {
			return nil, err
		}
		if s == AllScans {
			return allScanners, nil
		}
		scans = append(scans, s)
	}
	return scans, nil
}

// ParseScan parses the scan.
func ParseScan(s string) (ScanType, error) {
	switch s {
	case grypeStr:
		return Grype, nil
	case snykStr:
		return Snyk, nil
	case trivyStr:
		return Trivy, nil
	case osvStr:
		return OSV, nil
	default:
		return AllScans, fmt.Errorf("unknown scan: %s", s)
	}
}

// Options are the scan options.
type Options struct {
	// Image to scan
	Image string

	// Scan types
	Scans string
}

// Validate validates the options.
func (o *Options) Validate() error {
	if o.Image == "" {
		return fmt.Errorf("image is required")
	}

	if o.Scans == "" {
		o.Scans = allScannersStr
	}
	return nil
}
