package main

import (
	"flag"
	"os"

	"github.com/mchmarny/vulctl/pkg/types"
	"github.com/mchmarny/vulctl/pkg/vul"
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
	digest    = flag.String("digest", "", "digest of the source image")
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
		log.Error().Msg(err.Error())
		os.Exit(1)
	}

	os.Exit(0)
}

func printVersion() {
	log.Info().Str("version", version).Str("commit", commit).Str("date", date).Msg(name)
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
	f, err := types.ParseSourceFormat(*format)
	if err != nil {
		return errors.Wrap(err, "error parsing format")
	}

	opt := &types.InputOptions{
		Source: *digest,
		File:   *file,
		Output: output,
		Format: f,
	}

	if err := opt.Validate(); err != nil {
		return errors.Wrap(err, "error validating input")
	}

	if err := vul.Import(opt); err != nil {
		return errors.Wrap(err, "error executing command")
	}

	return nil
}
