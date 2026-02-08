package file

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/stretchr/testify/assert"
)

func TestFileImportJSON(t *testing.T) {
	t.Parallel()
	f := "test_json.json"
	list := makeVulns(3)
	defer os.Remove(f)
	err := Import(context.Background(), "file://"+f, list)
	assert.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(f)
	assert.NoError(t, err)
}

func TestFileImportCSV(t *testing.T) {
	t.Parallel()
	f := "test_csv.csv"
	list := makeVulns(3)
	defer os.Remove(f)
	err := Import(context.Background(), "file://"+f, list)
	assert.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(f)
	assert.NoError(t, err)
}

func TestFileImportEmptyURI(t *testing.T) {
	t.Parallel()
	err := Import(context.Background(), "", makeVulns(1))
	assert.Error(t, err)
}

func TestFileImportNilVulns(t *testing.T) {
	t.Parallel()
	err := Import(context.Background(), "file://test.json", nil)
	assert.Error(t, err)
}

func TestFileImportUnsupportedExtension(t *testing.T) {
	t.Parallel()
	f := "test.xml"
	defer os.Remove(f)
	err := Import(context.Background(), "file://"+f, makeVulns(1))
	assert.Error(t, err)
}

func TestFileImportEmptyList(t *testing.T) {
	t.Parallel()
	f := "test_empty.json"
	defer os.Remove(f)
	err := Import(context.Background(), "file://"+f, []*data.ImageVulnerability{})
	assert.NoError(t, err)
}

func makeVulns(num int) []*data.ImageVulnerability {
	list := make([]*data.ImageVulnerability, num)
	for i := range num {
		v := fmt.Sprintf("test%d", i)
		list[i] = &data.ImageVulnerability{
			Image:       v,
			Digest:      v,
			Source:      v,
			ProcessedAt: time.Now(),
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
