package main

import (
	"os"

	"github.com/mchmarny/vimp/internal/cmd"
)

var (
	// set at build time
	version = "v0.0.1-default"
)

func main() {
	cmd.Execute(version, os.Args)
}
