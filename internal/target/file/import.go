package file

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

// Import prints the vulnerabilities to stdout.
// file://data.json
// file://data.csv
func Import(uri string, vuls []*data.ImageVulnerability) error {
	if uri == "" {
		return errors.New("empty import target")
	}

	if vuls == nil {
		return errors.New("vulnerabilities required")
	}

	uri = strings.Replace(uri, "file://", "", 1)

	f, err := os.Create(uri)
	if err != nil {
		return errors.Wrap(err, "error opening the output file")
	}
	defer f.Close()

	ext := filepath.Ext(uri)
	switch ext {
	case ".json":
		return writeJSON(f, vuls)
	case ".csv":
		return writeCSV(f, vuls)
	default:
		return errors.Errorf("unsupported file type: %s", ext)
	}
}

// writeJSON writes the results to a file.
func writeJSON(f *os.File, results []*data.ImageVulnerability) error {
	if f == nil {
		return errors.New("file required")
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		return errors.Wrap(err, "error encoding the output to file")
	}

	return nil
}

// writeCSV writes the results to a file.
func writeCSV(f *os.File, results []*data.ImageVulnerability) error {
	if f == nil {
		return errors.New("file required")
	}

	w := csv.NewWriter(f)

	for _, r := range results {
		if err := w.Write(r.Strings()); err != nil {
			return errors.Wrap(err, "error writing record to file")
		}
	}

	w.Flush()

	if err := w.Error(); err != nil {
		return errors.Wrap(err, "error writing the output to file")
	}

	return nil
}
