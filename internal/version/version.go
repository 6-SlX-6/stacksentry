// Package version exposes build metadata for the StackSentry binary.
//
// Release builds inject values through -ldflags, for example:
//
//	go build -ldflags "-X github.com/6-SlX-6/stacksentry/internal/version.Version=0.1.0"
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// These variables are overridden at link time by release builds.
var (
	// Version is the semantic version of the scanner without a leading "v".
	Version = "0.1.0"
	// Commit is the source revision the binary was built from.
	Commit = ""
	// Date is the UTC build timestamp in RFC 3339 format.
	Date = ""
)

// Info describes the running binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	Date      string `json:"date,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the build information of the running binary. When the binary
// was built without link-time metadata (for example via "go install"), the
// VCS revision recorded by the Go toolchain is used as a fallback.
func Get() Info {
	info := Info{
		Version:   strings.TrimPrefix(Version, "v"),
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if info.Commit == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					info.Commit = s.Value
				case "vcs.time":
					if info.Date == "" {
						info.Date = s.Value
					}
				}
			}
		}
	}
	if len(info.Commit) > 12 {
		info.Commit = info.Commit[:12]
	}
	return info
}

// String renders a single human-readable version line.
func (i Info) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "stacksentry v%s", i.Version)
	var extra []string
	if i.Commit != "" {
		extra = append(extra, "commit "+i.Commit)
	}
	if i.Date != "" {
		extra = append(extra, "built "+i.Date)
	}
	extra = append(extra, i.GoVersion, i.Platform)
	fmt.Fprintf(&b, " (%s)", strings.Join(extra, ", "))
	return b.String()
}
