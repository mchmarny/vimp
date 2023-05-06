package target

import (
	"strings"

	"github.com/mchmarny/vimp/internal/target/bq"
	"github.com/mchmarny/vimp/internal/target/console"
	"github.com/mchmarny/vimp/internal/target/file"
	"github.com/mchmarny/vimp/internal/target/postgres"
	"github.com/mchmarny/vimp/internal/target/sqlite"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/mchmarny/vimp/pkg/query"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	expectedURIParts = 2

	bqType       = "bq"
	consoleType  = "console"
	fileType     = "file"
	sqliteType   = "sqlite"
	postgresType = "postgres"
)

// Importer is the interface for importers.
type Importer func(uri string, vuls []*data.ImageVulnerability) error

// Querier is the interface for queriers.
type Querier func(opt *query.Options) (any, error)

func GetSampleTargets() []string {
	list := []string{}
	list = append(list, sqlite.SampleURIs...)
	list = append(list, bq.SampleURIs...)
	list = append(list, file.SampleURIs...)
	list = append(list, console.SampleURIs...)
	list = append(list, postgres.SampleURIs...)
	return list
}

func getTargetPrefix(uri string) string {
	uri = strings.TrimSpace(uri)
	p := strings.Split(uri, "://")
	if len(p) != expectedURIParts {
		log.Error().Str("uri", uri).Msg("invalid target URI")
		return uri
	}
	return strings.ToLower(p[0])
}

// GetImporter returns importer for the given target.
func GetImporter(uri string) (Importer, error) {
	uri = getTargetPrefix(uri)

	switch uri {
	case bqType:
		return bq.Import, nil
	case consoleType:
		return console.Import, nil
	case fileType:
		return file.Import, nil
	case sqliteType:
		return sqlite.Import, nil
	case postgresType:
		return postgres.Import, nil
	default:
		return nil, errors.Errorf("unsupported import target type: %s", uri)
	}
}

// GetQuerier returns querier for the given target.
func GetQuerier(uri string) (Querier, error) {
	uri = getTargetPrefix(uri)

	switch uri {
	case sqliteType:
		return sqlite.Query, nil
	case postgresType:
		return postgres.Query, nil
	default:
		return nil, errors.Errorf("unsupported query target type: %s", uri)
	}
}
