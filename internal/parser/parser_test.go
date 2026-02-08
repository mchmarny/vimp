package parser

import (
	"testing"
)

func TestToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"empty string", "", ""},
		{"int", 42, "42"},
		{"float64", 3.14, "3.14"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ToString(tc.input)
			if got != tc.want {
				t.Errorf("ToString(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []any
		want  string
	}{
		{"all nil", []any{nil, nil}, ""},
		{"first non-nil", []any{"first", "second"}, "first"},
		{"skip nil", []any{nil, "second"}, "second"},
		{"skip empty", []any{"", "second"}, "second"},
		{"empty slice", []any{}, ""},
		{"single value", []any{"only"}, "only"},
		{"number after nil", []any{nil, 42}, "42"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := FirstNonEmpty(tc.input...)
			if got != tc.want {
				t.Errorf("FirstNonEmpty(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestToFloat32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input any
		want  float32
	}{
		{"nil", nil, 0},
		{"float32", float32(3.14), 3.14},
		{"float64", float64(2.71), 2.71},
		{"int", int(42), 42},
		{"int32", int32(100), 100},
		{"int64", int64(200), 200},
		{"uint", uint(10), 10},
		{"uint32", uint32(20), 20},
		{"uint64", uint64(30), 30},
		{"string", "not a number", 0},
		{"bool", true, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ToFloat32(tc.input)
			if got != tc.want {
				t.Errorf("ToFloat32(%v) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestToBool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input any
		want  bool
	}{
		{"nil", nil, false},
		{"bool true", true, true},
		{"bool false", false, false},
		{"string true", "true", true},
		{"string false", "false", false},
		{"string other", "yes", false},
		{"int", 1, false}, // not a bool, so false
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ToBool(tc.input)
			if got != tc.want {
				t.Errorf("ToBool(%v) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
