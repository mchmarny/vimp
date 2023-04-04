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

	// flags
	source    = flag.String("source", "", "Digest of the source image from which the vulnerability report was generated.")
	file      = flag.String("file", "", "Path to vulnerability report.")
	target    = flag.String("target", "", "Target data store (e.g. bq://project.dataset.table, file://path/to/file.json, stdout:// etc.)")
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
	fmt.Printf("%s - %s\n", name, version)
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
		Target: *target,
	}

	if err := processor.Process(opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
