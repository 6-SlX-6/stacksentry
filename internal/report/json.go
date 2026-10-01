package report

import (
	"encoding/json"
	"io"
)

// RenderJSON writes the report as indented JSON followed by a newline. The
// structure is documented in docs/json-report.md and
// docs/report.schema.json.
func RenderJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
