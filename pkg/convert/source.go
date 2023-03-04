package convert

import (
	"context"

	aa "google.golang.org/api/containeranalysis/v1"
)

type VulnerabilityConverter func(ctx context.Context, in []byte) ([]*aa.VulnerabilityOccurrence, error)
