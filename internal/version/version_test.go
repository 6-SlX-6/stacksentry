package version

import (
	"strings"
	"testing"
)

func TestGetAndString(t *testing.T) {
	oldV, oldC, oldD := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = oldV, oldC, oldD })

	Version, Commit, Date = "v1.2.3", "0123456789abcdef0123", "2026-10-01T00:00:00Z"
	info := Get()
	if info.Version != "1.2.3" || info.Commit != "0123456789ab" || info.Date != "2026-10-01T00:00:00Z" {
		t.Fatalf("Get() = %+v", info)
	}
	s := info.String()
	for _, want := range []string{"stacksentry v1.2.3", "commit 0123456789ab", "built 2026-10-01T00:00:00Z", info.GoVersion, info.Platform} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
	plain := Info{Version: "0.1.0", GoVersion: "go1.26.0", Platform: "linux/amd64"}.String()
	if plain != "stacksentry v0.1.0 (go1.26.0, linux/amd64)" {
		t.Fatalf("plain String() = %q", plain)
	}
}
