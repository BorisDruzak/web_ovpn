package helper

import "fmt"

// ContractError carries the stable machine-readable error code emitted by the
// helper. Messages are intentionally local and must never contain input data.
type ContractError struct {
	Code    string
	Message string
}

func (err *ContractError) Error() string {
	if err.Message == "" {
		return err.Code
	}
	return fmt.Sprintf("%s: %s", err.Code, err.Message)
}

func contractError(code, message string) error {
	return &ContractError{Code: code, Message: message}
}

// ErrorCode extracts a stable helper error code.
func ErrorCode(err error) string {
	if coded, ok := err.(*ContractError); ok {
		return coded.Code
	}
	return "internal_error"
}
