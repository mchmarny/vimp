package target

import (
	"strings"

	"github.com/mchmarny/vimp/internal/target/bq"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

const (
	expectedURIParts = 2
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
	case "bq":
		return bq.Import, nil
	default:
		return nil, errors.Errorf("unsupported import target type: %s", uri)
	}
}
