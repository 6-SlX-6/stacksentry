package compose

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
)

// ExtensionKey is the service-level extension used for documented
// exceptions, e.g.
//
//	x-stacksentry:
//	  ignore:
//	    - rule: SST-SEC-001
//	      reason: Traefik reads container labels through a socket proxy.
const ExtensionKey = "x-stacksentry"

func normalize(model *types.Project, files []sourceFile) *Project {
	p := &Project{Name: model.Name, WorkingDir: model.WorkingDir}
	for _, f := range files {
		p.Files = append(p.Files, f.display)
		p.Variables = append(p.Variables, f.raw.variables...)
		if f.raw.hasVersion {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"%s: the top-level \"version\" attribute is obsolete and ignored by Docker Compose; it can be removed.", f.display))
		}
		if f.raw.hasInclude {
			p.Limitations = append(p.Limitations, fmt.Sprintf(
				"%s uses \"include\"; included files are not analyzed in this version. Scan them separately.", f.display))
		}
	}

	all := map[string]types.ServiceConfig{}
	for name, svc := range model.Services {
		all[name] = svc
	}
	for name, svc := range model.DisabledServices {
		all[name] = svc
	}
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		svc, warnings := normalizeService(all[name])
		svc.File, svc.Line = locate(name, files)
		p.Services = append(p.Services, svc)
		p.Warnings = append(p.Warnings, warnings...)
	}
	return p
}

func locate(service string, files []sourceFile) (string, int) {
	for _, f := range files {
		if line, ok := f.raw.serviceLines[service]; ok {
			return f.display, line
		}
	}
	if len(files) > 0 {
		return files[0].display, 0
	}
	return "", 0
}

func normalizeService(s types.ServiceConfig) (Service, []string) {
	out := Service{
		Name:          s.Name,
		Image:         s.Image,
		HasBuild:      s.Build != nil,
		Privileged:    s.Privileged,
		NetworkMode:   s.NetworkMode,
		CapAdd:        normalizeCaps(s.CapAdd),
		CapDrop:       normalizeCaps(s.CapDrop),
		User:          s.User,
		ReadOnly:      s.ReadOnly,
		UseAPISocket:  s.UseAPISocket,
		Restart:       s.Restart,
		ContainerName: s.ContainerName,
		Command:       append([]string(nil), s.Command...),
		Entrypoint:    append([]string(nil), s.Entrypoint...),
	}
	for name := range s.Networks {
		out.Networks = append(out.Networks, name)
	}
	sort.Strings(out.Networks)

	for _, v := range s.Volumes {
		out.Mounts = append(out.Mounts, Mount{Type: v.Type, Source: v.Source, Target: v.Target, ReadOnly: v.ReadOnly})
	}
	for _, t := range s.Tmpfs {
		target, _, _ := strings.Cut(t, ":")
		out.Mounts = append(out.Mounts, Mount{Type: MountTmpfs, Target: target})
	}
	for _, port := range s.Ports {
		if port.Published == "" && port.HostIP == "" && port.Mode == "host" {
			// Swarm host-mode ports without a published port are not exposed.
			continue
		}
		out.Ports = append(out.Ports, Port{HostIP: port.HostIP, Published: port.Published, Target: port.Target, Protocol: port.Protocol})
	}
	if s.HealthCheck != nil {
		disabled := s.HealthCheck.Disable
		if len(s.HealthCheck.Test) > 0 && strings.EqualFold(s.HealthCheck.Test[0], "NONE") {
			disabled = true
		}
		out.Healthcheck = &Healthcheck{Disabled: disabled}
	}
	if s.Deploy != nil {
		if s.Deploy.RestartPolicy != nil {
			out.DeployRestartCondition = s.Deploy.RestartPolicy.Condition
		}
		if lim := s.Deploy.Resources.Limits; lim != nil {
			out.MemoryLimit = int64(lim.MemoryBytes)
			out.CPULimit = float64(lim.NanoCPUs)
		}
	}
	if out.MemoryLimit == 0 {
		out.MemoryLimit = int64(s.MemLimit)
	}
	if out.CPULimit == 0 {
		switch {
		case s.CPUS > 0:
			out.CPULimit = float64(s.CPUS)
		case s.CPUQuota > 0:
			period := s.CPUPeriod
			if period <= 0 {
				period = 100000
			}
			out.CPULimit = float64(s.CPUQuota) / float64(period)
		}
	}
	if s.StopGracePeriod != nil {
		d := time.Duration(*s.StopGracePeriod)
		out.StopGracePeriod = &d
	}

	for name, value := range s.Environment {
		e := EnvVar{Name: name}
		if value != nil {
			e.Value, e.HasValue = *value, true
		}
		out.Environment = append(out.Environment, e)
	}
	sort.Slice(out.Environment, func(i, j int) bool { return out.Environment[i].Name < out.Environment[j].Name })
	for _, f := range s.EnvFiles {
		out.EnvFiles = append(out.EnvFiles, f.Path)
	}

	if s.Logging != nil {
		out.Logging = Logging{Driver: s.Logging.Driver, Options: copyMap(s.Logging.Options)}
	}

	for name, dep := range s.DependsOn {
		out.DependsOn = append(out.DependsOn, Dependency{Service: name, Condition: dep.Condition})
	}
	sort.Slice(out.DependsOn, func(i, j int) bool { return out.DependsOn[i].Service < out.DependsOn[j].Service })

	ignore, warnings := parseIgnore(s.Name, s.Extensions[ExtensionKey])
	out.Ignore = ignore
	return out, warnings
}

func normalizeCaps(caps []string) []string {
	if len(caps) == 0 {
		return nil
	}
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		c = strings.ToUpper(strings.TrimSpace(c))
		out = append(out, strings.TrimPrefix(c, "CAP_"))
	}
	return out
}

func copyMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// parseIgnore reads x-stacksentry.ignore, which accepts rule IDs as plain
// strings or as {rule, reason} mappings. Malformed entries produce warnings
// rather than errors so that a typo never hides the rest of the scan.
func parseIgnore(service string, ext any) (map[string]string, []string) {
	if ext == nil {
		return nil, nil
	}
	var warnings []string
	warn := func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf("service %q: %s: ", service, ExtensionKey)+fmt.Sprintf(format, args...))
	}
	m, ok := ext.(map[string]any)
	if !ok {
		warn("expected a mapping with an \"ignore\" list")
		return nil, warnings
	}
	raw, ok := m["ignore"]
	if !ok {
		return nil, warnings
	}
	list, ok := raw.([]any)
	if !ok {
		warn("\"ignore\" must be a list of rule IDs")
		return nil, warnings
	}
	out := map[string]string{}
	for _, entry := range list {
		var id, reason string
		switch e := entry.(type) {
		case string:
			id = e
		case map[string]any:
			id, _ = e["rule"].(string)
			reason, _ = e["reason"].(string)
		}
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" {
			warn("ignored an entry without a rule ID")
			continue
		}
		reason = strings.TrimSpace(reason)
		if reason == "" {
			reason = "suppressed via " + ExtensionKey + " (no reason given)"
		}
		out[id] = reason
	}
	return out, warnings
}
