package scanner

// DefaultRegistry returns a registry with all built-in scanners registered.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewGrypeScanner())
	r.Register(NewTrivyScanner())
	r.Register(NewSnykScanner())
	r.Register(NewOSVScanner())
	return r
}

// defaultRegistry is the package-level registry initialized with all scanners.
var defaultRegistry = DefaultRegistry()

// GetScanner returns a scanner by name from the default registry.
func GetScanner(name string) (Scanner, bool) {
	return defaultRegistry.Get(name)
}

// GetAvailableScanners returns all available scanners from the default registry.
func GetAvailableScanners() []Scanner {
	return defaultRegistry.Available()
}

// GetAllScannerNames returns names of all registered scanners.
func GetAllScannerNames() []string {
	return defaultRegistry.Names()
}

// GetAvailableScannerNames returns names of all available scanners.
func GetAvailableScannerNames() []string {
	return defaultRegistry.AvailableNames()
}
