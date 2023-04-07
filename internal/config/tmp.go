package config

import (
	"fmt"
	"os"
	"path"
	"time"
)

// GetTempFilePath returns a temporary file path.
func GetTempFilePath(prefix string) string {
	f := fmt.Sprintf("%s-%d.json", prefix, time.Now().Nanosecond())
	return path.Join(os.TempDir(), f)
}
