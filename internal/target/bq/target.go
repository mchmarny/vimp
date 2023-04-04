package bq

import (
	"context"
	"strings"

	"cloud.google.com/go/bigquery"
	"github.com/pkg/errors"
)

const (
	importDefaultLocation   = "US"
	importTargetParts       = 3
	importTargetPartProject = 0
	importTargetPartDataset = 1
	importTargetPartTable   = 2

	expectedFormat = "bq://project.dataset.table"

	targetSchema = "bq://"
)

type targetConfig struct {
	ProjectID string
	Location  string
	DatasetID string
	TableID   string
}

// ParseImportRequest parses import request.
// e.g. bq://cloudy-demos.disco.packages
func parseTarget(uri string) (*targetConfig, error) {
	if !strings.HasPrefix(uri, "bq://") {
		return nil, errors.Errorf("invalid import target schema, expected %s, got: %s", targetSchema, uri)
	}

	v := strings.Replace(uri, targetSchema, "", 1)

	parts := strings.Split(v, ".")
	if len(parts) != importTargetParts {
		return nil, errors.Errorf("invalid import target: %s, expected %d part format: %s", uri, importTargetParts, expectedFormat)
	}

	t := &targetConfig{
		Location:  importDefaultLocation,
		ProjectID: parts[importTargetPartProject],
		DatasetID: parts[importTargetPartDataset],
		TableID:   parts[importTargetPartTable],
	}

	if t.ProjectID == "" || t.DatasetID == "" || t.TableID == "" {
		return nil, errors.Errorf("invalid import target: %+v", t)
	}

	return t, nil
}

func insert(ctx context.Context, t *targetConfig, items interface{}) error {
	if t == nil || t.ProjectID == "" || t.DatasetID == "" || t.TableID == "" {
		return errors.New("project, dataset and table must be specified")
	}

	client, err := bigquery.NewClient(ctx, t.ProjectID)
	if err != nil {
		return errors.Wrap(err, "failed to create bigquery client")
	}
	defer client.Close()

	inserter := client.Dataset(t.DatasetID).Table(t.TableID).Inserter()
	inserter.SkipInvalidRows = true
	if err := inserter.Put(ctx, items); err != nil {
		return errors.Wrap(err, "failed to insert rows")
	}

	return nil
}
