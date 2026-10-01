package compose

import "fmt"

// ErrorKind classifies why loading a Compose project failed.
type ErrorKind string

// Load error kinds.
const (
	ErrNotFound       ErrorKind = "not_found"
	ErrPermission     ErrorKind = "permission_denied"
	ErrRead           ErrorKind = "read_error"
	ErrInvalidYAML    ErrorKind = "invalid_yaml"
	ErrUnsupported    ErrorKind = "unsupported_structure"
	ErrInvalidCompose ErrorKind = "invalid_compose"
	ErrNoServices     ErrorKind = "no_services"
)

// LoadError describes a failure to load a Compose project. All load errors
// are user input problems and map to exit code 2.
type LoadError struct {
	Kind ErrorKind
	Path string
	// Detail is a human readable explanation.
	Detail string
	Err    error
}

// Error implements error.
func (e *LoadError) Error() string {
	switch e.Kind {
	case ErrNotFound:
		if e.Detail != "" {
			return fmt.Sprintf("%q: %s", e.Path, e.Detail)
		}
		return fmt.Sprintf("compose file %q not found", e.Path)
	case ErrPermission:
		return fmt.Sprintf("cannot read compose file %q: permission denied", e.Path)
	case ErrInvalidYAML:
		return fmt.Sprintf("invalid YAML in %q: %s", e.Path, e.Detail)
	case ErrUnsupported:
		return fmt.Sprintf("unsupported Compose structure in %q: %s", e.Path, e.Detail)
	case ErrInvalidCompose:
		return fmt.Sprintf("invalid Compose configuration in %q: %s", e.Path, e.Detail)
	case ErrNoServices:
		return fmt.Sprintf("%q defines no services%s", e.Path, e.Detail)
	default:
		return fmt.Sprintf("cannot read compose file %q: %s", e.Path, e.Detail)
	}
}

// Unwrap returns the underlying error.
func (e *LoadError) Unwrap() error { return e.Err }
