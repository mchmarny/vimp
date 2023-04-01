package main

import (
	"testing"
)

func TestLogging(t *testing.T) {
	debug := true
	initLogging(&debug)
	t.Logf("test")
}
