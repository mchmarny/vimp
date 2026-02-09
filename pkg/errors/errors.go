package errors

import "fmt"

// ErrorCode represents a structured error classification.
type ErrorCode string

const (
	// ErrCodeInvalidInput indicates malformed or invalid input.
	ErrCodeInvalidInput ErrorCode = "INVALID_INPUT"
	// ErrCodeNotFound indicates a requested resource was not found.
	ErrCodeNotFound ErrorCode = "NOT_FOUND"
	// ErrCodeIO indicates a file or I/O operation error.
	ErrCodeIO ErrorCode = "IO_ERROR"
	// ErrCodeDatabase indicates a database operation error.
	ErrCodeDatabase ErrorCode = "DATABASE_ERROR"
	// ErrCodeConversion indicates a data conversion or parsing error.
	ErrCodeConversion ErrorCode = "CONVERSION_ERROR"
	// ErrCodeScanner indicates a scanner execution error.
	ErrCodeScanner ErrorCode = "SCANNER_ERROR"
	// ErrCodeTimeout indicates an operation exceeded its time limit.
	ErrCodeTimeout ErrorCode = "TIMEOUT"
	// ErrCodeInternal indicates an internal system error.
	ErrCodeInternal ErrorCode = "INTERNAL"
)

// StructuredError provides structured error information for better observability.
// It includes an error code for programmatic handling, a human-readable message,
// the underlying cause, and optional context for debugging.
type StructuredError struct {
	Code    ErrorCode
	Message string
	Cause   error
	Context map[string]any
}

// Error implements the error interface.
func (e *StructuredError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause for errors.Is and errors.As support.
func (e *StructuredError) Unwrap() error {
	return e.Cause
}

// New creates a new StructuredError with the given code and message.
func New(code ErrorCode, message string) *StructuredError {
	return &StructuredError{
		Code:    code,
		Message: message,
	}
}

// NewWithContext creates a new StructuredError with context information.
func NewWithContext(code ErrorCode, message string, context map[string]any) *StructuredError {
	return &StructuredError{
		Code:    code,
		Message: message,
		Context: context,
	}
}

// Wrap wraps an existing error with additional context.
func Wrap(code ErrorCode, message string, cause error) *StructuredError {
	return &StructuredError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// WrapWithContext wraps an error with additional context information.
func WrapWithContext(code ErrorCode, message string, cause error, context map[string]any) *StructuredError {
	return &StructuredError{
		Code:    code,
		Message: message,
		Cause:   cause,
		Context: context,
	}
}

// Wrapf wraps an error with a formatted message.
func Wrapf(code ErrorCode, cause error, format string, args ...any) *StructuredError {
	return &StructuredError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Cause:   cause,
	}
}

// Newf creates a new StructuredError with a formatted message.
func Newf(code ErrorCode, format string, args ...any) *StructuredError {
	return &StructuredError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}
