package query

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

const (
	// TypeImage represents the image query type.
	ByNothing Type = iota
	ByImage
	ByDigest
	ByCVE
)

// Type represents the query type.
type Type int64

// Options represents the input options.
type Options struct {
	// Image is the URI of the image from which the report was generated.
	Image string

	// Digest is the sha:256 digest of the image.
	Digest string

	// CVE is the CVE ID to query.
	CVE string

	// Target is the target data store uri.
	Target string

	// DiffsOnly indicates if only diffs should be returned.
	DiffsOnly bool
}

func (o *Options) String() string {
	return fmt.Sprintf("Options{Image: %s, Digest: %s, CVE: %s, Target: %s}", o.Image, o.Digest, o.CVE, o.Target)
}

// GetTope returns the query type.
// TODO: this is a bit of a hack, need to refactor
func (o *Options) GetTope() Type {
	if o.CVE == "" && o.Digest == "" && o.Image == "" {
		return ByNothing
	}

	if o.CVE == "" && o.Digest == "" {
		return ByImage
	}

	if o.CVE == "" {
		return ByDigest
	}

	return ByCVE
}

// Validate validates the options.
func (o *Options) Validate() error {
	if o.Target == "" {
		return errors.New("target is required")
	}

	if o.Image == "" {
		return errors.New("image is required")
	}

	if strings.Contains(o.Image, "@") {
		imageParts := strings.Split(o.Image, "@")
		o.Image = imageParts[0]
		o.Digest = imageParts[1]
	}

	u, err := url.Parse(o.Image)
	if err != nil {
		return errors.Wrap(err, "error parsing source")
	}
	if u.Scheme != "" {
		u.Scheme = "https"
	}
	o.Image = u.String()

	return nil
}
