package docker

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// Inspector collects a Snapshot from a Docker daemon.
type Inspector struct {
	Conn *Connection
	// HostFS is the host root filesystem used to read daemon configuration
	// and /proc. It may be nil, in which case those checks are skipped.
	HostFS fs.FS
	// GOOS is the operating system StackSentry runs on.
	GOOS string
}

// Inspect gathers the snapshot. It is best-effort: failures of individual
// API calls are recorded as limitations instead of aborting the scan.
func (in *Inspector) Inspect(ctx context.Context) *Snapshot {
	api := in.Conn.API
	s := &Snapshot{Endpoint: in.Conn.Endpoint}
	limit := func(format string, args ...any) {
		s.Limitations = append(s.Limitations, fmt.Sprintf(format, args...))
	}

	if v, err := api.ServerVersion(ctx, client.ServerVersionOptions{}); err == nil {
		s.Daemon.Version, s.Daemon.APIVersion = v.Version, v.APIVersion
		s.Daemon.OSType, s.Daemon.Architecture = v.Os, v.Arch
	} else {
		limit("Docker version information could not be read: %v", err)
	}

	if res, err := api.Info(ctx, client.InfoOptions{}); err == nil {
		info := res.Info
		s.Daemon.OperatingSystem = info.OperatingSystem
		s.Daemon.KernelVersion = info.KernelVersion
		s.Daemon.Name = info.Name
		s.Daemon.RootDir = info.DockerRootDir
		s.Daemon.Warnings = append([]string(nil), info.Warnings...)
		s.ImagesTotal = info.Images
		for _, opt := range info.SecurityOptions {
			if strings.Contains(opt, "rootless") {
				s.Daemon.Rootless = true
			}
		}
		if s.Daemon.OSType == "" {
			s.Daemon.OSType = info.OSType
		}
		if s.Daemon.Architecture == "" {
			s.Daemon.Architecture = info.Architecture
		}
	} else {
		limit("Daemon information (docker info) could not be read: %v", err)
	}

	in.collectContainers(ctx, s, limit)

	if res, err := api.ImageList(ctx, client.ImageListOptions{Filters: make(client.Filters).Add("dangling", "true")}); err == nil {
		for _, img := range res.Items {
			s.DanglingImages = append(s.DanglingImages, Image{ID: shortID(img.ID), Size: img.Size})
		}
		sort.Slice(s.DanglingImages, func(i, j int) bool { return s.DanglingImages[i].ID < s.DanglingImages[j].ID })
	} else {
		limit("The image list could not be read: %v", err)
	}

	if du, err := api.DiskUsage(ctx, client.DiskUsageOptions{Containers: true, Images: true, Volumes: true, BuildCache: true}); err == nil {
		s.DiskUsage = &DiskUsage{
			Images:     UsageItem{Count: du.Images.TotalCount, Size: du.Images.TotalSize, Reclaimable: du.Images.Reclaimable},
			Containers: UsageItem{Count: du.Containers.TotalCount, Size: du.Containers.TotalSize, Reclaimable: du.Containers.Reclaimable},
			Volumes:    UsageItem{Count: du.Volumes.TotalCount, Size: du.Volumes.TotalSize, Reclaimable: du.Volumes.Reclaimable},
			BuildCache: UsageItem{Count: du.BuildCache.TotalCount, Size: du.BuildCache.TotalSize, Reclaimable: du.BuildCache.Reclaimable},
		}
	} else {
		limit("Docker disk usage (docker system df) could not be read: %v", err)
	}

	probe := listenerProbe{fsys: in.HostFS, goos: in.GOOS, endpoint: in.Conn.Endpoint, tls: in.Conn.TLS}
	s.Listeners, s.Limitations = probe.run(s.Daemon.Warnings, s.Limitations)
	return s
}

func (in *Inspector) collectContainers(ctx context.Context, s *Snapshot, limit func(string, ...any)) {
	list, err := in.Conn.API.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		limit("The container list could not be read: %v", err)
		return
	}
	failed := 0
	for _, summary := range list.Items {
		c := Container{
			ID:          shortID(summary.ID),
			Name:        containerName(summary.Names, summary.ID),
			Image:       summary.Image,
			State:       string(summary.State),
			Running:     summary.State == container.StateRunning,
			NetworkMode: summary.HostConfig.NetworkMode,
			Mounts:      convertMounts(summary.Mounts),
		}
		if c.Running {
			res, err := in.Conn.API.ContainerInspect(ctx, summary.ID, client.ContainerInspectOptions{})
			if err != nil {
				failed++
			} else {
				applyInspect(&c, res.Container)
			}
		}
		s.Containers = append(s.Containers, c)
	}
	sort.Slice(s.Containers, func(i, j int) bool { return s.Containers[i].Name < s.Containers[j].Name })
	if failed > 0 {
		limit("%d running container(s) could not be inspected; privileged mode and restart policy checks are incomplete.", failed)
	}
}

func applyInspect(c *Container, resp container.InspectResponse) {
	c.Inspected = true
	if resp.Config != nil && resp.Config.Image != "" {
		c.Image = resp.Config.Image
	}
	if hc := resp.HostConfig; hc != nil {
		c.Privileged = hc.Privileged
		c.NetworkMode = string(hc.NetworkMode)
		c.RestartPolicy = string(hc.RestartPolicy.Name)
		c.AutoRemove = hc.AutoRemove
	}
	if len(resp.Mounts) > 0 {
		c.Mounts = convertMounts(resp.Mounts)
	}
}

func convertMounts(points []container.MountPoint) []Mount {
	out := make([]Mount, 0, len(points))
	for _, m := range points {
		out = append(out, Mount{Type: string(m.Type), Source: m.Source, Destination: m.Destination, RW: m.RW})
	}
	return out
}

func containerName(names []string, id string) string {
	for _, n := range names {
		n = strings.TrimPrefix(n, "/")
		if n != "" && !strings.Contains(n, "/") {
			return n
		}
	}
	return shortID(id)
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
