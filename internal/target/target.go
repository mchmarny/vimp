package target

import (
	"strings"

	"github.com/mchmarny/vimp/internal/target/bq"
	"github.com/mchmarny/vimp/internal/target/console"
	"github.com/mchmarny/vimp/internal/target/file"
	"github.com/mchmarny/vimp/internal/target/sqlite"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

const (
	expectedURIParts = 2

	// BQType is the BigQuery importer type
	BQType = "bq"
	// StdoutType is the stdout importer type
	ConsoleType = "console"
	// FileType is the file importer type
	FileType = "file"
	// SQLiteType is the sqlite importer type
	SQLiteType = "sqlite"
)

var (
	// ImporterTypes is the list of supported importer types.
	ImporterTypes = []string{BQType, ConsoleType, FileType}
)

// Importer is the interface for importers.
type Importer func(uri string, vuls []*data.ImageVulnerability) error

// GetImporter returns importer for the given target.
func GetImporter(uri string) (Importer, error) {
	if uri == "" {
		return nil, errors.New("empty import target")
	}

	uri = strings.TrimSpace(uri)
	p := strings.Split(uri, "://")
	if len(p) != expectedURIParts {
		return nil, errors.Errorf("invalid import target format: %s", uri)
	}

	switch strings.ToLower(p[0]) {
	case BQType:
		return bq.Import, nil
	case ConsoleType:
		return console.Import, nil
	case FileType:
		return file.Import, nil
	case SQLiteType:
		return sqlite.Import, nil
	default:
		return nil, errors.Errorf("unsupported import target type: %s", uri)
	}
}
