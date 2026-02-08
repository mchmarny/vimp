package converter

import (
	"context"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/vimp/pkg/data"
	"github.com/pkg/errors"
)

// Converter defines the interface for vulnerability scanner output converters.
type Converter interface {
	// Name returns the converter's identifier (e.g., "grype", "trivy").
	Name() string

	// CanHandle returns true if this converter can process the given JSON container.
	CanHandle(c *gabs.Container) bool

	// Convert transforms scanner output into normalized vulnerabilities.
	Convert(ctx context.Context, c *gabs.Container) ([]*data.Vulnerability, error)
}

// Registry manages registered converters and provides detection/lookup.
type Registry struct {
	converters []Converter
}

// NewRegistry creates a new converter registry with all available converters.
func NewRegistry() *Registry {
	return &Registry{
		converters: make([]Converter, 0),
	}
}

// Register adds a converter to the registry.
func (r *Registry) Register(c Converter) {
	r.converters = append(r.converters, c)
}

// Detect attempts to find a converter that can handle the given JSON container.
func (r *Registry) Detect(c *gabs.Container) (Converter, error) {
	if c == nil {
		return nil, errors.New("container is nil")
	}

	for _, conv := range r.converters {
		if conv.CanHandle(c) {
			return conv, nil
		}
	}

	return nil, errors.New("no converter found for the given format")
}

// Get returns a converter by name, or nil if not found.
func (r *Registry) Get(name string) (Converter, bool) {
	for _, conv := range r.converters {
		if conv.Name() == name {
			return conv, true
		}
	}
	return nil, false
}

// Names returns the names of all registered converters.
func (r *Registry) Names() []string {
	names := make([]string, len(r.converters))
	for i, conv := range r.converters {
		names[i] = conv.Name()
	}
	return names
}

// All returns all registered converters.
func (r *Registry) All() []Converter {
	return r.converters
}
