package report

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// RenderOptions controls rendering for all formats.
type RenderOptions struct {
	Format Format
	Table  TableOptions
}

// Render writes the report in the requested format.
func Render(w io.Writer, r *Report, opts RenderOptions) error {
	switch opts.Format {
	case FormatJSON:
		return RenderJSON(w, r)
	case FormatMarkdown:
		return RenderMarkdown(w, r)
	case FormatTable, "":
		return RenderTable(w, r, opts.Table)
	default:
		return fmt.Errorf("unsupported format %q", opts.Format)
	}
}

// WriteFile renders the report and writes it to path atomically: the
// content is written to a temporary file in the same directory and renamed
// into place, so readers never observe a partially written report. The file
// is created with mode 0600 because reports describe infrastructure details.
func WriteFile(path string, r *Report, opts RenderOptions) (err error) {
	var buf bytes.Buffer
	if err := Render(&buf, r, opts); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("cannot write report to %q: %w", path, unwrapPathError(err))
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cannot write report to %q: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("cannot write report to %q: %w", path, err)
	}
	if err = os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("cannot write report to %q: %w", path, err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("cannot write report to %q: %w", path, unwrapPathError(err))
	}
	return nil
}

func unwrapPathError(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	return err
}
