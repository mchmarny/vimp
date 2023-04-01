package parser

func ToFloat32(v interface{}) float32 {
	if v == nil {
		return 0
	}

	switch v := v.(type) {
	case float32:
		return v
	case float64: // TODO: handle overflow
		return float32(v)
	case int:
		return float32(v)
	case int32:
		return float32(v)
	case int64:
		return float32(v)
	case uint:
		return float32(v)
	case uint32:
		return float32(v)
	case uint64:
		return float32(v)
	}
	return 0
}
