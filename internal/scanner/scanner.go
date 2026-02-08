package scanner

import (
	"context"
)

// Scanner defines the interface for vulnerability scanners.
type Scanner interface {
	// Name returns the scanner's identifier (e.g., "grype", "trivy").
	Name() string

	// IsAvailable returns true if the scanner is installed and available.
	IsAvailable() bool

	// Scan runs the scanner against the given image and returns the output file path.
	Scan(ctx context.Context, image string) (outputPath string, err error)

	// ConverterName returns the name of the converter to use for this scanner's output.
	ConverterName() string
}

// Registry manages registered scanners and provides lookup.
type Registry struct {
	scanners []Scanner
}

// NewRegistry creates a new scanner registry.
func NewRegistry() *Registry {
	return &Registry{
		scanners: make([]Scanner, 0),
	}
}

// Register adds a scanner to the registry.
func (r *Registry) Register(s Scanner) {
	r.scanners = append(r.scanners, s)
}

// Get returns a scanner by name, or nil if not found.
func (r *Registry) Get(name string) (Scanner, bool) {
	for _, s := range r.scanners {
		if s.Name() == name {
			return s, true
		}
	}
	return nil, false
}

// Available returns all scanners that are currently available (installed).
func (r *Registry) Available() []Scanner {
	available := make([]Scanner, 0)
	for _, s := range r.scanners {
		if s.IsAvailable() {
			available = append(available, s)
		}
	}
	return available
}

// All returns all registered scanners.
func (r *Registry) All() []Scanner {
	return r.scanners
}

// Names returns the names of all registered scanners.
func (r *Registry) Names() []string {
	names := make([]string, len(r.scanners))
	for i, s := range r.scanners {
		names[i] = s.Name()
	}
	return names
}

// AvailableNames returns the names of all available scanners.
func (r *Registry) AvailableNames() []string {
	available := r.Available()
	names := make([]string, len(available))
	for i, s := range available {
		names[i] = s.Name()
	}
	return names
}
