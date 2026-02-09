package errors

import (
	"errors"
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()

	err := New(ErrCodeNotFound, "file not found")

	if err.Code != ErrCodeNotFound {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeNotFound)
	}
	if err.Message != "file not found" {
		t.Errorf("Message = %v, want %v", err.Message, "file not found")
	}
	if err.Cause != nil {
		t.Errorf("Cause = %v, want nil", err.Cause)
	}
}

func TestNewf(t *testing.T) {
	t.Parallel()

	err := Newf(ErrCodeNotFound, "file %s not found", "test.json")

	if err.Message != "file test.json not found" {
		t.Errorf("Message = %v, want %v", err.Message, "file test.json not found")
	}
}

func TestWrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("original error")
	err := Wrap(ErrCodeIO, "failed to read file", cause)

	if err.Code != ErrCodeIO {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeIO)
	}
	if err.Cause != cause {
		t.Errorf("Cause = %v, want %v", err.Cause, cause)
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is should return true for wrapped error")
	}
}

func TestWrapf(t *testing.T) {
	t.Parallel()

	cause := errors.New("original error")
	err := Wrapf(ErrCodeDatabase, cause, "query failed for table %s", "vul")

	if err.Message != "query failed for table vul" {
		t.Errorf("Message = %v, want %v", err.Message, "query failed for table vul")
	}
	if err.Cause != cause {
		t.Errorf("Cause = %v, want %v", err.Cause, cause)
	}
}

func TestNewWithContext(t *testing.T) {
	t.Parallel()

	ctx := map[string]any{
		"image":   "redis:latest",
		"scanner": "grype",
	}
	err := NewWithContext(ErrCodeScanner, "scanner failed", ctx)

	if err.Context == nil {
		t.Fatal("Context should not be nil")
	}
	if err.Context["image"] != "redis:latest" {
		t.Errorf("Context[image] = %v, want %v", err.Context["image"], "redis:latest")
	}
}

func TestWrapWithContext(t *testing.T) {
	t.Parallel()

	cause := errors.New("timeout")
	ctx := map[string]any{
		"timeout": "5m",
	}
	err := WrapWithContext(ErrCodeTimeout, "operation timed out", cause, ctx)

	if err.Cause != cause {
		t.Errorf("Cause = %v, want %v", err.Cause, cause)
	}
	if err.Context["timeout"] != "5m" {
		t.Errorf("Context[timeout] = %v, want %v", err.Context["timeout"], "5m")
	}
}

func TestError(t *testing.T) {
	t.Parallel()

	t.Run("without cause", func(t *testing.T) {
		t.Parallel()
		err := New(ErrCodeNotFound, "resource missing")
		expected := "[NOT_FOUND] resource missing"
		if err.Error() != expected {
			t.Errorf("Error() = %v, want %v", err.Error(), expected)
		}
	})

	t.Run("with cause", func(t *testing.T) {
		t.Parallel()
		cause := errors.New("file does not exist")
		err := Wrap(ErrCodeIO, "failed to open", cause)
		expected := "[IO_ERROR] failed to open: file does not exist"
		if err.Error() != expected {
			t.Errorf("Error() = %v, want %v", err.Error(), expected)
		}
	})
}

func TestUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying error")
	err := Wrap(ErrCodeInternal, "wrapper", cause)

	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrorsAs(t *testing.T) {
	t.Parallel()

	err := New(ErrCodeConversion, "failed to convert")

	var structErr *StructuredError
	if !errors.As(err, &structErr) {
		t.Error("errors.As should return true for StructuredError")
	}
	if structErr.Code != ErrCodeConversion {
		t.Errorf("Code = %v, want %v", structErr.Code, ErrCodeConversion)
	}
}
