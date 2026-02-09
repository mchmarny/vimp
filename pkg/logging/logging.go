package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// ANSI color codes
const (
	colorGreen = "\033[32m"
	colorReset = "\033[0m"
	colorRed   = "\033[31m"
)

// CLIHandler is a custom slog.Handler for CLI output.
type CLIHandler struct {
	writer io.Writer
	level  slog.Level
}

// NewCLIHandler creates a new CLI handler that writes to the given writer.
func NewCLIHandler(w io.Writer, level slog.Level) *CLIHandler {
	return &CLIHandler{
		writer: w,
		level:  level,
	}
}

// Enabled returns true if the handler handles records at the given level.
func (h *CLIHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle formats and writes the log record with attributes.
func (h *CLIHandler) Handle(_ context.Context, r slog.Record) error {
	msg := r.Message

	// Append attributes as key=value pairs
	if r.NumAttrs() > 0 {
		var attrs []string
		r.Attrs(func(a slog.Attr) bool {
			attrs = append(attrs, fmt.Sprintf("%s=%v", a.Key, a.Value))
			return true
		})
		if len(attrs) > 0 {
			msg = msg + ": " + strings.Join(attrs, " ")
		}
	}

	// Add color for error messages and success messages
	if r.Level >= slog.LevelError {
		msg = colorRed + msg + colorReset
	} else {
		msg = colorGreen + msg + colorReset
	}

	_, err := fmt.Fprintln(h.writer, msg)
	return err
}

// WithAttrs returns a new handler with the given attributes.
func (h *CLIHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

// WithGroup returns a new handler with the given group.
func (h *CLIHandler) WithGroup(_ string) slog.Handler {
	return h
}

// NewCLILogger creates a new logger with CLI-friendly output format.
func NewCLILogger(level slog.Level) *slog.Logger {
	handler := NewCLIHandler(os.Stderr, level)
	return slog.New(handler)
}

// SetDefaultCLILogger initializes the CLI logger and sets it as the default.
func SetDefaultCLILogger(level slog.Level) {
	slog.SetDefault(NewCLILogger(level))
}

// ParseLogLevel converts a string to slog.Level.
func ParseLogLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
