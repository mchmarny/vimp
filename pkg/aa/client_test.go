package aa

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func createTestClient(ctx context.Context) (*http.Client, error) {
	return &http.Client{}, nil
}

func TestClientGet(t *testing.T) {
	ctx := context.Background()
	client = createTestClient
	url := "https://api.github.com/users/mchmarny"

	var d map[string]interface{}
	err := Get(ctx, url, &d)
	assert.NoError(t, err)
}
