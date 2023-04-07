package scanner

import (
	"fmt"
	"os/exec"
)

func makeTrivyCmd(digest, path string) *exec.Cmd {
	return exec.Command("trivy", "image", "--quiet", "--security-checks", "vuln", "--format", "json", "--no-progress", "--output", path, digest)
}

func makeSnykCmd(digest, path string) *exec.Cmd {
	jfo := fmt.Sprintf("--json-file-output=%s", path)
	return exec.Command("snyk", "container", "test", "--app-vulns", jfo, digest)
}

func makeGrypeCmd(digest, path string) *exec.Cmd {
	return exec.Command("grype", "-q", "--add-cpes-if-none", "-s", "AllLayers", "-o", "json", "--file", path, digest)
}
