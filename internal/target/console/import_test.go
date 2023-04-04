package console

import (
	"fmt"
	"testing"
	"time"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/stretchr/testify/assert"
)

func TestConsoleImport(t *testing.T) {
	list := makeVulns(3)
	err := Import("console://stdout", list)
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
