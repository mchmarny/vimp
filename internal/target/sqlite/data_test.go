package sqlite

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/mchmarny/vimp/pkg/query"
	"github.com/stretchr/testify/assert"
)

const (
	testFile = "./test.db"
)

func deleteDB() {
	os.Remove(testFile)
}

func TestData(t *testing.T) {
	deleteDB()
	defer deleteDB()

	uri := fmt.Sprintf("sqlite://%s", testFile)
	list := makeVulns(3)

	err := Import(uri, list)
	assert.NoError(t, err)

	err = Import(uri, list)
	assert.NoError(t, err)

	_, err = Query(&query.Options{
		Target: uri,
	})
	assert.NoError(t, err)
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
				CVE:      v,
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
