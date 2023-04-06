package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// FileNameDefault is the default file name for the data store.
	FileNameDefault = ".vimp.db"

	// LocalStorePrefix is the prefix for local store.
	LocalStorePrefix = "sqlite://"
)

// GetDefaultDBPath returns the default path for the data store.
func GetDefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Sprintf("%s%s", LocalStorePrefix, FileNameDefault)
	}
	return fmt.Sprintf("%s%s", LocalStorePrefix, filepath.Join(home, FileNameDefault))
}
