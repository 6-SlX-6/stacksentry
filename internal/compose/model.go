// Package compose loads Docker Compose files and normalizes them into the
// model analyzed by StackSentry's Compose rules.
package compose

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// Project is the normalized view of one Compose project.
type Project struct {
	// Name is the Compose project name.
	Name string
	// Files are the Compose files as given by the user, in merge order.
	Files []string
	// WorkingDir is the absolute project directory.
	WorkingDir string
	// Services are sorted by name and include services gated by profiles.
	Services []Service
	// Variables are interpolation references without a default value.
	Variables []VariableRef
	// Warnings are parser messages worth surfacing to the user.
	Warnings []string
	// Limitations describe parts of the configuration that were not analyzed.
	Limitations []string
}

// Service returns the service with the given name.
func (p *Project) Service(name string) (*Service, bool) {
	for i := range p.Services {
		if p.Services[i].Name == name {
			return &p.Services[i], true
		}
	}
	return nil, false
}

// ServiceNames returns the sorted service names.
func (p *Project) ServiceNames() []string {
	names := make([]string, 0, len(p.Services))
	for _, s := range p.Services {
		names = append(names, s.Name)
	}
	return names
}

// Service is the normalized configuration of one Compose service.
type Service struct {
	Name string
	// File and Line locate the service definition; Line is 0 when unknown.
	File string
	Line int

	Image    string
	HasBuild bool

	Privileged   bool
	NetworkMode  string
	Networks     []string
	CapAdd       []string
	CapDrop      []string
	User         string
	ReadOnly     bool
	UseAPISocket bool

	Mounts []Mount
	Ports  []Port

	Healthcheck *Healthcheck

	Restart                string
	DeployRestartCondition string
	ContainerName          string
	StopGracePeriod        *time.Duration

	Environment []EnvVar
	EnvFiles    []string
	Command     []string
	Entrypoint  []string

	MemoryLimit int64
	CPULimit    float64
	Logging     Logging

	DependsOn []Dependency

	// Ignore maps rule IDs to the reason given in x-stacksentry.ignore.
	Ignore map[string]string
}

// Env returns the environment variable with the given name.
func (s *Service) Env(name string) (EnvVar, bool) {
	for _, e := range s.Environment {
		if e.Name == name {
			return e, true
		}
	}
	return EnvVar{}, false
}

// Mount types as used by the Compose specification.
const (
	MountBind   = "bind"
	MountVolume = "volume"
	MountTmpfs  = "tmpfs"
	MountNpipe  = "npipe"
)

// Mount is a volume, bind mount, tmpfs or named pipe attached to a service.
type Mount struct {
	Type     string
	Source   string
	Target   string
	ReadOnly bool
}

// String renders the mount in Compose short syntax.
func (m Mount) String() string {
	var b strings.Builder
	if m.Source != "" {
		b.WriteString(m.Source)
		b.WriteString(":")
	}
	b.WriteString(m.Target)
	if m.ReadOnly {
		b.WriteString(":ro")
	}
	return b.String()
}

// IsHostPath reports whether the mount exposes a path from the host.
func (m Mount) IsHostPath() bool {
	return m.Type == MountBind || m.Type == MountNpipe
}

// Exposure classifies on which host interfaces a port is published.
type Exposure int

// Exposure levels.
const (
	ExposureAllInterfaces Exposure = iota
	ExposureSpecificInterface
	ExposureLoopback
)

// String describes the exposure for evidence output.
func (e Exposure) String() string {
	switch e {
	case ExposureLoopback:
		return "localhost only"
	case ExposureSpecificInterface:
		return "specific host interface"
	default:
		return "all host interfaces"
	}
}

// Port is a published port mapping.
type Port struct {
	HostIP    string
	Published string
	Target    uint32
	Protocol  string
}

// Exposure classifies the host binding of the port.
func (p Port) Exposure() Exposure {
	host := strings.Trim(p.HostIP, "[]")
	switch {
	case host == "" || host == "0.0.0.0" || host == "::":
		return ExposureAllInterfaces
	case strings.EqualFold(host, "localhost"):
		return ExposureLoopback
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return ExposureLoopback
	}
	return ExposureSpecificInterface
}

// String renders the mapping in Compose short syntax, e.g.
// "127.0.0.1:5432:5432/tcp". A missing host port is shown as an empty
// segment, which Docker interprets as a random host port.
func (p Port) String() string {
	var b strings.Builder
	if p.HostIP != "" {
		host := p.HostIP
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]"
		}
		b.WriteString(host)
		b.WriteString(":")
	}
	if p.Published != "" || p.HostIP != "" {
		b.WriteString(p.Published)
		b.WriteString(":")
	}
	b.WriteString(strconv.FormatUint(uint64(p.Target), 10))
	if p.Protocol != "" {
		b.WriteString("/")
		b.WriteString(p.Protocol)
	}
	return b.String()
}

// Healthcheck is the Compose healthcheck configuration of a service.
type Healthcheck struct {
	Disabled bool
}

// EnvVar is one entry of a service's environment section. HasValue is false
// for entries such as "- DEBUG" that pass a variable through from the
// environment Compose runs in.
type EnvVar struct {
	Name     string
	Value    string
	HasValue bool
}

// Logging is the logging configuration of a service. An empty Driver means
// the Docker daemon's default driver is used.
type Logging struct {
	Driver  string
	Options map[string]string
}

// Dependency is one depends_on entry.
type Dependency struct {
	Service   string
	Condition string
}

// VariableRef is an interpolation expression such as ${NAME} that has no
// default value.
type VariableRef struct {
	Name string
	// Expression is the expression as written, e.g. "${NAME}" or "$NAME".
	Expression string
	File       string
	Line       int
	// Path is the YAML path of the value, e.g. services.app.environment.URL.
	Path string
	// Service is the service the reference belongs to, if any.
	Service string
}
