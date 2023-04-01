package utils

import "fmt"

// ToBool converts interface to bool.
// Hack to avoid panics when converting gabs data to string.
func ToBool(v interface{}) bool {
	if v == nil {
		return false
	}

	b, ok := v.(bool)
	if ok {
		return b
	}

	return fmt.Sprintf("%v", v) == "true"
}
