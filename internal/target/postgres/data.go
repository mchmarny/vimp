package postgres

import (
	"context"
	"embed"

	"github.com/jackc/pgx/v5"
	"github.com/pkg/errors"
)

var (
	//go:embed sql/*
	f embed.FS

	SampleURIs = []string{
		"postgres://username:password@localhost:5432/db",
		"postgres://localhost/db?user=other&password=secret",
		"postgres://localhost/db",
	}
)

func getDB(ctx context.Context, uri string) (*pgx.Conn, error) {
	if uri == "" {
		return nil, errors.New("missing data uri")
	}

	conn, err := pgx.Connect(ctx, uri)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to database: %s", uri)
	}

	// the ddl script is idempotent so we can run it every time
	b, err := f.ReadFile("sql/ddl.sql")
	if err != nil {
		return nil, errors.Wrap(err, "failed to read the schema creation file")
	}

	// will create schema if it does not exist
	if _, err := conn.Exec(ctx, string(b)); err != nil {
		return nil, errors.Wrapf(err, "failed to create database schema in: %s", uri)
	}

	return conn, nil
}
