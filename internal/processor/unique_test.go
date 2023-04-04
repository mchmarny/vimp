package processor

import (
	"testing"

	"github.com/mchmarny/vimp/pkg/data"
	"github.com/stretchr/testify/assert"
)

func TestUnique(t *testing.T) {
	t.Parallel()

	items := []*data.Vulnerability{
		{
			CVE:     "CVE-2019-0001",
			Package: "test",
			Version: "1.0.0",
		},
		{
			CVE:     "CVE-2019-0002",
			Package: "test2",
			Version: "2.0.0",
		},
		{
			CVE:     "CVE-2019-0001",
			Package: "test",
			Version: "1.0.0",
		},
	}

	assert.Equal(t, 2, len(Unique(items)))
}
