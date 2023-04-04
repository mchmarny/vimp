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

	bqType      = "bq"
	consoleType = "console"
	fileType    = "file"
	sqliteType  = "sqlite"
)

// Importer is the interface for importers.
type Importer func(uri string, vuls []*data.ImageVulnerability) error

func GetSampleTargets() []string {
	list := []string{}
	list = append(list, sqlite.SampleURIs...)
	list = append(list, bq.SampleURIs...)
	list = append(list, file.SampleURIs...)
	list = append(list, console.SampleURIs...)
	return list
}

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
	case bqType:
		return bq.Import, nil
	case consoleType:
		return console.Import, nil
	case fileType:
		return file.Import, nil
	case sqliteType:
		return sqlite.Import, nil
	default:
		return nil, errors.Errorf("unsupported import target type: %s", uri)
	}
}
