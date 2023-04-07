package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllScanners(t *testing.T) {
	o := &Options{
		Image: "docker.io/redis@sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448",
	}

	r, err := Scan(o)
	assert.NoError(t, err)
	assert.NotNil(t, r)
	assert.Len(t, r.Files, 3)
}
