package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mchmarny/vulctl/internal/processor"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	name = "vulctl"

	// set at build time
	version = "v0.0.1-default"
	commit  = "none"
	date    = "unknown"

	// flags
	source    = flag.String("source", "", "digest of the source image")
	file      = flag.String("file", "", "path to vulnerability report file")
	format    = flag.String("format", "", "scanner used to generate that file (e.g. grype, snyk, trivy)")
	output    = flag.String("output", "", "path to write results to")
	isVerbose = flag.Bool("verbose", false, "verbose output")
	doVersion = flag.Bool("version", false, "print version and exit")
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
		printUsage()
		log.Error().Msg(err.Error())
		os.Exit(1)
	}

	os.Exit(0)
}

func printVersion() {
	fmt.Printf("%s - %s (commit: %s - build: %s)\n", name, version, commit, date)
}

func printUsage() {
	fmt.Printf(`

usage:
  %s [flags]

flags:
  --source   <digest> (required)
  --file     <path>   (required)
  --format   <format> (required, e.g. grype, snyk, trivy)
  --output   <path>   (optional, defaults to stdout)
  --verbose           (optional, prints debug logs, defaults to false)
  --version           (optional, prints version and exits)

`, name)
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
		Format: *format,
		Output: output,
	}

	if err := processor.Process(opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
