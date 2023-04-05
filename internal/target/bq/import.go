package bq

import (
	"context"

	"cloud.google.com/go/bigquery"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	columnImage     = "image"
	columnDigest    = "digest"
	columnSource    = "source"
	columnProcessed = "processed"
	columnExposure  = "exposure"
	columnPackage   = "package"
	columnVersion   = "version"
	columnSeverity  = "severity"
	columnScore     = "score"
	columnFixed     = "fixed"
)

var (
	SampleURIs = []string{
		"bq://project.dataset.table",
	}

	vulnerabilitySchema = bigquery.Schema{
		{Name: columnImage, Type: bigquery.StringFieldType, Required: true},
		{Name: columnDigest, Type: bigquery.StringFieldType, Required: true},
		{Name: columnSource, Type: bigquery.StringFieldType, Required: true},
		{Name: columnProcessed, Type: bigquery.TimestampFieldType, Required: true},
		{Name: columnExposure, Type: bigquery.StringFieldType, Required: true},
		{Name: columnPackage, Type: bigquery.StringFieldType, Required: true},
		{Name: columnVersion, Type: bigquery.StringFieldType, Required: true},
		{Name: columnSeverity, Type: bigquery.StringFieldType, Required: true},
		{Name: columnScore, Type: bigquery.FloatFieldType, Required: true},
		{Name: columnFixed, Type: bigquery.BooleanFieldType, Required: true},
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
		columnImage:     v.vul.Image,
		columnDigest:    v.vul.Digest,
		columnSource:    v.vul.Source,
		columnProcessed: v.vul.ProcessedAt,
		columnExposure:  v.vul.Exposure,
		columnPackage:   v.vul.Package,
		columnVersion:   v.vul.Version,
		columnSeverity:  v.vul.Severity,
		columnScore:     v.vul.Score,
		columnFixed:     v.vul.IsFixed,
	}, "", nil
}
