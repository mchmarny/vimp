package utils

import "fmt"

// ToString converts interface to string.
// Hack to avoid panics when converting gabs data to string.
func ToString(v interface{}) string {
	if v == nil {
		return ""
	}

	s, ok := v.(string)
	if ok {
		return s
	}

	return fmt.Sprintf("%v", v)
}
