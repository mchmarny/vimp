package bq

import (
	"context"
	"strings"

	"cloud.google.com/go/bigquery"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/iterator"
)

func configureTarget(ctx context.Context, t *targetConfig) error {
	if t == nil {
		return errors.New("nil target config")
	}

	log.Debug().
		Str("project", t.ProjectID).
		Str("dataset", t.DatasetID).
		Str("table", t.TableID).
		Msg("configuring target")

	exists, err := datasetExists(ctx, t)
	if err != nil {
		return errors.Wrap(err, "failed to check if dataset exists")
	}

	if !exists {
		if err := createDataset(ctx, t); err != nil {
			return errors.Wrap(err, "failed to create dataset")
		}
	}

	exists, err = tableExists(ctx, t)
	if err != nil {
		return errors.Wrap(err, "failed to check if table exists")
	}

	if !exists {
		if err := createTable(ctx, t, vulnerabilitySchema); err != nil {
			return errors.Wrapf(err, "failed to create table with ID: %s", t.TableID)
		}
	}

	return nil
}

func createTable(ctx context.Context, t *targetConfig, schema bigquery.Schema) error {
	client, err := bigquery.NewClient(ctx, t.ProjectID)
	if err != nil {
		return errors.Wrapf(err, "failed to create bigquery client for project %s", t.ProjectID)
	}
	defer client.Close()

	metaData := &bigquery.TableMetadata{
		Schema: schema,
	}

	tableRef := client.Dataset(t.DatasetID).Table(t.TableID)
	if err := tableRef.Create(ctx, metaData); err != nil {
		return errors.Wrapf(err, "failed to create table %s", t.TableID)
	}
	return nil
}

func createDataset(ctx context.Context, t *targetConfig) error {
	client, err := bigquery.NewClient(ctx, t.ProjectID)
	if err != nil {
		return errors.Wrapf(err, "failed to create bigquery client for project %s", t.ProjectID)
	}
	defer client.Close()

	meta := &bigquery.DatasetMetadata{Location: t.Location}
	if err := client.Dataset(t.DatasetID).Create(ctx, meta); err != nil {
		return errors.Wrapf(err, "failed to create dataset %s", t.DatasetID)
	}
	return nil
}

func datasetExists(ctx context.Context, t *targetConfig) (bool, error) {
	client, err := bigquery.NewClient(ctx, t.ProjectID)
	if err != nil {
		return false, errors.Wrapf(err, "failed to create bigquery client for project %s", t.ProjectID)
	}
	defer client.Close()

	it := client.Datasets(ctx)
	for {
		dataset, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return false, errors.Wrapf(err, "failed to list datasets for project %s", t.ProjectID)
		}

		if strings.EqualFold(dataset.DatasetID, t.DatasetID) {
			return true, nil
		}
	}
	return false, nil
}

func tableExists(ctx context.Context, t *targetConfig) (bool, error) {
	client, err := bigquery.NewClient(ctx, t.ProjectID)
	if err != nil {
		return false, errors.Wrapf(err, "failed to create bigquery client for project %s", t.ProjectID)
	}
	defer client.Close()

	it := client.Dataset(t.DatasetID).Tables(ctx)
	for {
		table, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return false, errors.Wrapf(err, "failed to list datasets for project %s", t.ProjectID)
		}

		if strings.EqualFold(table.TableID, t.TableID) {
			return true, nil
		}
	}
	return false, nil
}
