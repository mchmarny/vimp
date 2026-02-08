package processor

import (
	"github.com/mchmarny/vimp/internal/converter"
)

// defaultRegistry holds the default converter registry.
var defaultRegistry = converter.DefaultRegistry()

// GetConverterNames returns the names of all available converters.
func GetConverterNames() []string {
	return defaultRegistry.Names()
}
