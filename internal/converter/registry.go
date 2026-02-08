package converter

import (
	"github.com/mchmarny/vimp/internal/converter/anchore"
	"github.com/mchmarny/vimp/internal/converter/clair"
	"github.com/mchmarny/vimp/internal/converter/grype"
	"github.com/mchmarny/vimp/internal/converter/osv"
	"github.com/mchmarny/vimp/internal/converter/snyk"
	"github.com/mchmarny/vimp/internal/converter/trivy"
)

// DefaultRegistry returns a registry with all built-in converters registered.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(grype.New())
	r.Register(trivy.New())
	r.Register(snyk.New())
	r.Register(clair.New())
	r.Register(osv.New())
	r.Register(anchore.New())
	return r
}
