package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"

	// sqlite3 driver
	_ "modernc.org/sqlite"
)

const (
	dataDriver string = "sqlite"
)

var (
	//go:embed sql/*
	f embed.FS

	driverPrefix = fmt.Sprintf("%s://", dataDriver)
)

func getStore(ctx context.Context, path string) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("directory not specified")
	}

	// remove driver prefix
	path = strings.Replace(path, driverPrefix, "", 1)

	wasCreated := false
	slog.Debug("data path", "path", path)

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		slog.Debug("data file does not exist, creating...")
		wasCreated = true
	}

	db, err := sql.Open(dataDriver, fmt.Sprintf("%s?parseTime=true", path))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open database: %s", path)
	}

	if wasCreated {
		slog.Debug("creating schema...")

		b, err := f.ReadFile("sql/ddl.sql")
		if err != nil {
			return nil, errors.Wrap(err, "failed to read the schema creation file")
		}
		if _, err := db.ExecContext(ctx, string(b)); err != nil {
			return nil, errors.Wrapf(err, "failed to create database schema in: %s", path)
		}
	}

	return db, nil
}

func parseTime(v string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		slog.Error("failed to parse time", "error", err, "value", v)
		return time.Now().UTC()
	}
	return t
}
