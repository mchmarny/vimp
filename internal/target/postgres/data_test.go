package postgres

import (
	"fmt"
	"testing"
	"time"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/mchmarny/vimp/pkg/query"
	"github.com/stretchr/testify/assert"
)

/*
docker run \
	--name postgres \
	-e POSTGRES_USER=test \
	-e POSTGRES_PASSWORD=test \
	-p 5432:5432 \
	-v ${PWD}/data:/var/lib/postgresql/data \
	-d postgres
*/

const (
	testConnection = "postgres://test:test@localhost:5432/test"
)

func TestData(t *testing.T) {
	list := makeVulns(3)

	err := Import(testConnection, list)
	assert.NoError(t, err)

	err = Import(testConnection, list)
	assert.NoError(t, err)

	r, err := Query(&query.Options{
		Target: testConnection,
	})
	assert.NoError(t, err)
	assert.NotNil(t, r)

	d := r.(map[string]*query.ImageResult)
	assert.Equal(t, 3, len(d))
}

func makeVulns(num int) []*data.ImageVulnerability {
	list := make([]*data.ImageVulnerability, num)
	for i := 0; i < num; i++ {
		v := fmt.Sprintf("test%d", i)
		list[i] = &data.ImageVulnerability{
			Image:       v,
			Digest:      v,
			Source:      v,
			ProcessedAt: time.Now().UTC(),
			Vulnerability: &data.Vulnerability{
				Exposure: v,
				Package:  v,
				Version:  v,
				Severity: v,
				Score:    float32(i),
				IsFixed:  num%2 == 0,
			},
		}
	}
	return list
}
