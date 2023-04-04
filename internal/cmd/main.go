package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mchmarny/vimp/internal/processor"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	name = "vimp"

	// set at build time
	version = "v0.0.1-default"
	commit  = "none"
	date    = "unknown"

	// flags
	source    = flag.String("source", "", "Digest of the source image from which the vulnerability report was generated.")
	file      = flag.String("file", "", "Path to vulnerability report.")
	format    = flag.String("format", "", "Scanner used to generate vulnerability report (e.g. grype, snyk, trivy). Auto-detected if not specified.")
	output    = flag.String("output", "", "Path to where results should be written (default: stdout).")
	isCSV     = flag.Bool("csv", false, "Output as CSV (default: json). Only supported when output specified.")
	isVerbose = flag.Bool("verbose", false, "Verbose output (default: false)")
	doVersion = flag.Bool("version", false, "Print version (default: false)")
)

func main() {
	flag.Parse()
	initLogging(isVerbose)

	if *doVersion {
		printVersion()
		os.Exit(0)
	}

	if err := execute(); err != nil {
		printVersion()
		log.Error().Msg(err.Error())
		os.Exit(1)
	}

	os.Exit(0)
}

func printVersion() {
	fmt.Printf("%s - %s (commit: %s - build: %s)\n", name, version, commit, date)
}

func initLogging(verbose *bool) {
	level := zerolog.InfoLevel
	if *verbose {
		level = zerolog.DebugLevel
	}

	zerolog.SetGlobalLevel(level)

	out := zerolog.ConsoleWriter{
		Out: os.Stderr,
		PartsExclude: []string{
			zerolog.TimestampFieldName,
		},
	}

	log.Logger = zerolog.New(out)
}

func execute() error {
	opt := &processor.Options{
		Source: *source,
		File:   *file,
		Format: format,
		Output: output,
		CSV:    *isCSV,
	}

	if err := processor.Process(opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
