package docker

import "github.com/6-SlX-6/stacksentry/internal/findings"

// Snapshot is a read-only view of a Docker host collected for host rules.
type Snapshot struct {
	Endpoint string
	Daemon   Daemon
	// Containers lists all containers, running and stopped, sorted by name.
	Containers []Container
	// ImagesTotal is the number of images reported by the daemon.
	ImagesTotal int
	// DanglingImages are untagged images not referenced by any tag.
	DanglingImages []Image
	// DiskUsage is nil when the daemon did not provide usage data.
	DiskUsage *DiskUsage
	// Listeners are observations of TCP API listeners.
	Listeners []ListenerObservation
	// Limitations describe information that could not be collected.
	Limitations []string
}

// Daemon describes the Docker daemon.
type Daemon struct {
	Version         string
	APIVersion      string
	OperatingSystem string
	OSType          string
	Architecture    string
	KernelVersion   string
	Name            string
	RootDir         string
	Rootless        bool
	Warnings        []string
}

// Container describes one container.
type Container struct {
	ID      string
	Name    string
	Image   string
	State   string
	Running bool
	// Inspected is true when detailed configuration was read.
	Inspected     bool
	Privileged    bool
	NetworkMode   string
	RestartPolicy string
	AutoRemove    bool
	Mounts        []Mount
}

// Mount is a mount point of a container.
type Mount struct {
	Type        string
	Source      string
	Destination string
	RW          bool
}

// Image is an image summary.
type Image struct {
	ID   string
	Size int64
}

// DiskUsage summarizes Docker's disk usage by object type.
type DiskUsage struct {
	Images     UsageItem
	Containers UsageItem
	Volumes    UsageItem
	BuildCache UsageItem
}

// Total returns the combined size of all object types.
func (d DiskUsage) Total() int64 {
	return d.Images.Size + d.Containers.Size + d.Volumes.Size + d.BuildCache.Size
}

// Reclaimable returns the combined reclaimable size of all object types.
func (d DiskUsage) Reclaimable() int64 {
	return d.Images.Reclaimable + d.Containers.Reclaimable + d.Volumes.Reclaimable + d.BuildCache.Reclaimable
}

// UsageItem is the usage of one object type.
type UsageItem struct {
	Count       int64
	Size        int64
	Reclaimable int64
}

// ListenerObservation is evidence that the Docker API listens on TCP.
type ListenerObservation struct {
	// Source names where the observation came from.
	Source string
	// Address is the listening address, e.g. tcp://0.0.0.0:2375.
	Address string
	// Detail adds context such as missing TLS verification.
	Detail     string
	Confidence findings.Confidence
}
