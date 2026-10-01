// Package imageref parses container image references and classifies how
// reproducible they are. It intentionally avoids network access: it only
// looks at the reference string.
package imageref

import (
	"strings"
)

// Reference is a parsed image reference such as
// "ghcr.io/org/app:1.2.3@sha256:abc...".
type Reference struct {
	Raw string
	// Registry is the registry host, empty for Docker Hub.
	Registry string
	// Repository is the repository path without registry. Docker Hub
	// official images are returned without the "library/" prefix.
	Repository string
	Tag        string
	Digest     string
}

// Parse splits an image reference into its parts. It never fails; invalid
// references simply produce empty fields.
func Parse(s string) Reference {
	ref := Reference{Raw: strings.TrimSpace(s)}
	rest := ref.Raw
	if strings.HasPrefix(rest, "sha256:") {
		// A bare image ID is immutable.
		ref.Digest = rest
		return ref
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		ref.Digest = rest[at+1:]
		rest = rest[:at]
	}
	if colon := strings.LastIndex(rest, ":"); colon > strings.LastIndex(rest, "/") {
		ref.Tag = rest[colon+1:]
		rest = rest[:colon]
	}
	if slash := strings.Index(rest, "/"); slash >= 0 {
		first := rest[:slash]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			ref.Registry = first
			rest = rest[slash+1:]
		}
	}
	if ref.Registry == "" || ref.Registry == "docker.io" || ref.Registry == "index.docker.io" {
		rest = strings.TrimPrefix(rest, "library/")
	}
	ref.Repository = strings.ToLower(rest)
	return ref
}

// TagKind classifies how mutable a reference is.
type TagKind int

// Tag kinds, from most to least reproducible.
const (
	// KindDigest means the reference is pinned to an immutable digest.
	KindDigest TagKind = iota
	// KindVersion is a tag containing a version number, e.g. 1.2.3 or 16-alpine.
	KindVersion
	// KindChannel is a moving tag without any version number, e.g. stable.
	KindChannel
	// KindLatest is the "latest" tag or a variant of it.
	KindLatest
	// KindUntagged has neither tag nor digest and resolves to latest.
	KindUntagged
)

// Kind classifies the reference.
func (r Reference) Kind() TagKind {
	switch {
	case r.Digest != "":
		return KindDigest
	case r.Tag == "":
		return KindUntagged
	}
	tag := strings.ToLower(r.Tag)
	for _, token := range strings.FieldsFunc(tag, func(c rune) bool { return c == '-' || c == '_' || c == '.' }) {
		if token == "latest" {
			return KindLatest
		}
	}
	if strings.ContainsAny(tag, "0123456789") {
		return KindVersion
	}
	return KindChannel
}
