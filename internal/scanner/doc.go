// Package scanner provides pluggable vulnerability scanner execution.
//
// Scanners execute external CLI tools to scan container images and produce
// JSON reports. Each scanner knows how to invoke its tool and which
// converter to use for parsing its output.
//
// Available scanners:
//   - grype: Anchore Grype (if installed)
//   - trivy: Aqua Security Trivy (if installed)
//   - snyk: Snyk CLI (if installed and authenticated)
//   - osv: Google OSV-Scanner (if installed)
//
// The Registry provides scanner discovery and lookup:
//
//	registry := scanner.DefaultRegistry()
//	available := registry.Available() // only installed scanners
//	for _, s := range available {
//	    path, err := s.Scan(ctx, "docker.io/redis:latest")
//	    // path contains JSON output file
//	}
//
// To add a new scanner, implement the Scanner interface:
//
//	type Scanner interface {
//	    Name() string
//	    IsAvailable() bool
//	    Scan(ctx context.Context, image string) (outputPath string, err error)
//	    ConverterName() string
//	}
package scanner
