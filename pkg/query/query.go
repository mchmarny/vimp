package query

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	// FileNameDefault is the default file name for the data store.
	FileNameDefault = ".vimp.db"

	// TypeImage represents the image query type.
	Undefined Query = iota
	Images
	Digests
	Exposure
	Packages
)

// Type represents the query type.
type Query int64

// String returns the string representation of the query type.
func (q Query) String() string {
	switch q {
	case Images:
		return "images"
	case Digests:
		return "digests"
	case Exposure:
		return "exposure"
	case Packages:
		return "packages"
	default:
		return "undefined"
	}
}

// Options represents the input options.
type Options struct {
	// Image is the URI of the image from which the report was generated.
	Image string

	// Digest is the sha:256 digest of the image.
	Digest string

	// Exposure is the CVE ID to query.
	Exposure string

	// Target is the target data store uri.
	Target string

	// DiffsOnly indicates if only diffs should be returned.
	DiffsOnly bool
}

func (o *Options) String() string {
	return fmt.Sprintf("image: %s, digest: %s, exposure: %s, target: %s, diffsOnly: %t}",
		o.Image, o.Digest, o.Exposure, o.Target, o.DiffsOnly)
}

// GetTope returns the query type.
// TODO: this is a bit of a hack, need to refactor
func (o *Options) GetQuery() (Query, error) {
	// if nothing set, return all images
	if o.Exposure == "" && o.Digest == "" && o.Image == "" {
		return Images, nil
	}

	if o.Exposure == "" && o.Digest == "" {
		return Digests, nil
	}

	if o.Exposure == "" {
		return Exposure, nil
	}

	return Packages, nil
}

// Validate validates the options.
func (o *Options) Validate() error {
	if o.Image != "" {
		if strings.Contains(o.Image, "@") {
			imageParts := strings.Split(o.Image, "@")
			o.Image = imageParts[0]
			o.Digest = imageParts[1]
		}

		u, err := url.Parse(o.Image)
		if err != nil {
			return errors.Wrap(err, "error parsing source")
		}
		if u.Scheme == "" {
			u.Scheme = "https"
		}
		o.Image = u.String()
	}

	if o.Target == "" {
		path, err := getDefaultDBPath()
		if err != nil {
			return errors.Wrap(err, "error getting default db path")
		}
		o.Target = path
	}

	return nil
}

func getDefaultDBPath() (path string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "failed to get user home dir")
	}
	log.Debug().Msgf("home dir: %s", home)

	return filepath.Join(home, FileNameDefault), nil
}
