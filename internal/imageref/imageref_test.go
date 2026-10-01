package imageref

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in                          string
		registry, repo, tag, digest string
	}{
		{"postgres", "", "postgres", "", ""},
		{"postgres:16.4", "", "postgres", "16.4", ""},
		{"library/redis:7", "", "redis", "7", ""},
		{"docker.io/library/nginx:1.27-alpine", "docker.io", "nginx", "1.27-alpine", ""},
		{"ghcr.io/Org/App:v1.2.3", "ghcr.io", "org/app", "v1.2.3", ""},
		{"localhost:5000/team/svc:dev", "localhost:5000", "team/svc", "dev", ""},
		{"localhost/svc", "localhost", "svc", "", ""},
		{"bitnami/postgresql:16", "", "bitnami/postgresql", "16", ""},
		{"n8nio/n8n:1.64.0@sha256:abcd", "", "n8nio/n8n", "1.64.0", "sha256:abcd"},
		{"nginx@sha256:abcd", "", "nginx", "", "sha256:abcd"},
		{"sha256:0123", "", "", "", "sha256:0123"},
		{"registry.example.com:5000/app", "registry.example.com:5000", "app", "", ""},
		{"", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			r := Parse(tt.in)
			if r.Registry != tt.registry || r.Repository != tt.repo || r.Tag != tt.tag || r.Digest != tt.digest {
				t.Fatalf("Parse(%q) = %+v", tt.in, r)
			}
		})
	}
}

func TestKind(t *testing.T) {
	tests := []struct {
		in   string
		want TagKind
	}{
		{"postgres", KindUntagged},
		{"postgres:latest", KindLatest},
		{"postgres:LATEST", KindLatest},
		{"app:latest-alpine", KindLatest},
		{"app:alpine-latest", KindLatest},
		{"app:stable", KindChannel},
		{"app:main", KindChannel},
		{"python:alpine", KindChannel},
		{"app:1.2.3", KindVersion},
		{"app:v1.2.3", KindVersion},
		{"postgres:16", KindVersion},
		{"nginx:1.27-alpine", KindVersion},
		{"app:latest@sha256:abc", KindDigest},
		{"app@sha256:abc", KindDigest},
		{"sha256:abc", KindDigest},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := Parse(tt.in).Kind(); got != tt.want {
				t.Fatalf("Kind(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
