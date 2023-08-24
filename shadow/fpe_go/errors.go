package fpe

import "fmt"

const (
	E_Go = iota
	S_FALSE
	E_POINTER
	E_INVALIDARG
	E_OUTOFMEMORY
	E_UNEXPECTED
	COR_E_IO
	COR_E_INVALIDOPERATION
)

type FPEError struct {
	msg  string
	code int64
}

// newFPEError creates a new CustomError with the given code.
func newFPEError(msg string, code int64) *FPEError {
	return &FPEError{msg: msg, code: code}
}

// Error implements the error interface.
func (e *FPEError) Error() string {
	switch e.code {
	case E_Go:
		return fmt.Sprintf("fpe error: %v", e.msg)
	case E_POINTER:
		return fmt.Sprintf("%v, C lib error: empty pointer", e.msg)
	case E_INVALIDARG:
		return fmt.Sprintf("%v, C lib error: invalid argument", e.msg)
	case E_OUTOFMEMORY:
		return fmt.Sprintf("%v, C lib error: out of memory", e.msg)
	default:
		return fmt.Sprintf("unknown error, C lib error code: %d", e.code)
	}
}
