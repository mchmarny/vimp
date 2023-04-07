package scanner

// Result is the scan result.
type Result struct {
	// Image to scan
	Image string `json:"image"`

	Files map[ScanType]string `json:"files"`
}
