package bq

import (
	"context"

	"cloud.google.com/go/bigquery"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var (
	SampleURIs = []string{
		"bq://project.dataset.table",
	}

	vulnerabilitySchema = bigquery.Schema{
		{Name: "image", Type: bigquery.StringFieldType, Required: true},
		{Name: "digest", Type: bigquery.StringFieldType, Required: true},
		{Name: "source", Type: bigquery.StringFieldType, Required: true},
		{Name: "processed", Type: bigquery.TimestampFieldType, Required: true},
		{Name: "cve", Type: bigquery.StringFieldType, Required: true},
		{Name: "package", Type: bigquery.StringFieldType, Required: true},
		{Name: "version", Type: bigquery.StringFieldType, Required: true},
		{Name: "severity", Type: bigquery.StringFieldType, Required: true},
		{Name: "score", Type: bigquery.FloatFieldType, Required: true},
		{Name: "fixed", Type: bigquery.BooleanFieldType, Required: true},
	}
)

func Import(uri string, vuls []*data.ImageVulnerability) error {
	t, err := parseTarget(uri)
	if err != nil {
		return errors.Wrap(err, "failed to parse target")
	}

	ctx := context.Background()
	if err := configureTarget(ctx, t); err != nil {
		return errors.Wrap(err, "errors checking target configuration")
	}

	rows := makeVulnerabilityRows(vuls)
	if err := insert(ctx, t, rows); err != nil {
		return errors.Wrap(err, "failed to insert rows")
	}

	log.Info().Msgf("inserted %d records into %s.%s.%s", len(rows), t.ProjectID, t.DatasetID, t.TableID)

	return nil
}

func makeVulnerabilityRows(in []*data.ImageVulnerability) []*VulnerabilityRow {
	list := make([]*VulnerabilityRow, 0)

	for _, r := range in {
		list = append(list, &VulnerabilityRow{
			vul: r,
		})
	}

	return list
}

type VulnerabilityRow struct {
	vul *data.ImageVulnerability
}

func (v *VulnerabilityRow) Save() (map[string]bigquery.Value, string, error) {
	return map[string]bigquery.Value{
		"image":     v.vul.Image,
		"digest":    v.vul.Digest,
		"source":    v.vul.Source,
		"processed": v.vul.ProcessedAt,
		"cve":       v.vul.CVE,
		"package":   v.vul.Package,
		"version":   v.vul.Version,
		"severity":  v.vul.Severity,
		"score":     v.vul.Score,
		"fixed":     v.vul.IsFixed,
	}, "", nil
}
