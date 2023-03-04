package aa

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	htransport "google.golang.org/api/transport/http"
)

const (
	scopeDefault = "https://www.googleapis.com/auth/cloud-platform"
)

var (
	client        clientProvider = createHTTPClientWithCredentials
	clientTimeout                = time.Second * 600
)

type clientProvider func(ctx context.Context) (*http.Client, error)

func Get(ctx context.Context, url string, resp any) error {
	if url == "" {
		return errors.New("url is empty")
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return errors.Wrap(err, "error creating request")
	}
	return Exec(ctx, req, resp)
}

func Submit(ctx context.Context, url string, content, resp any) error {
	if url == "" {
		return errors.New("url is empty")
	}

	if content == nil {
		return errors.New("content is nil")
	}

	b, err := json.Marshal(content)
	if err != nil {
		return errors.Wrap(err, "error marshaling content")
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(b))
	if err != nil {
		return errors.Wrap(err, "error creating request")
	}
	return Exec(ctx, req, resp)
}

func Exec(ctx context.Context, req *http.Request, resp any) error {
	if req == nil {
		return errors.New("request is nil")
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	cctx, cancel := context.WithTimeout(ctx, clientTimeout)
	defer cancel()
	c, err := client(cctx)
	if err != nil {
		return errors.Wrap(err, "error creating client")
	}

	r, err := c.Do(req)
	if err != nil {
		return errors.Wrap(err, "error executing request")
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return errors.Wrapf(err, "error getting projects: %s", r.Status)
	}

	if resp == nil {
		return nil
	}

	if err := json.NewDecoder(r.Body).Decode(resp); err != nil {
		return errors.Wrap(err, "error decoding response")
	}
	return nil
}

func createHTTPClientWithCredentials(ctx context.Context) (*http.Client, error) {
	var ops []option.ClientOption

	creds, err := google.FindDefaultCredentials(ctx, scopeDefault)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create default credentials")
	}

	ops = append(ops, option.WithCredentials(creds))
	c, _, err := htransport.NewClient(ctx, ops...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create http client")
	}

	return c, nil
}
