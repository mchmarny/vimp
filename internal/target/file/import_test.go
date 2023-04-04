package file

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/stretchr/testify/assert"
)

func TestFileImport(t *testing.T) {
	f := "test.json"
	list := makeVulns(3)
	defer os.Remove("test.json")
	err := Import("file://"+f, list)
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
			ProcessedAt: time.Now(),
			Vulnerability: &data.Vulnerability{
				ID:       v,
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
