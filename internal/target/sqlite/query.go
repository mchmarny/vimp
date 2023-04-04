package sqlite

import (
	"database/sql"

	"github.com/pkg/errors"
)

// Query returns all rows from the table.
// TODO: implement
func Query(uri string) (interface{}, error) {
	db, err := getStore(uri)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get store")
	}

	stmt, err := db.Prepare("SELECT val FROM not_implemented WHERE id >= ?")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to prepare select statement")
	}

	rows, err := stmt.Query()
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, errors.Wrapf(err, "failed to execute select statement")
	}
	defer rows.Close()

	list := make([]string, 0)
	for rows.Next() {
		var val string
		if err := rows.Scan(&val); err != nil {
			return nil, errors.Wrapf(err, "failed to scan row")
		}
		list = append(list, val)
	}

	return list, nil
}
