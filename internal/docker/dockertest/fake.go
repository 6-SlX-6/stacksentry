// Package dockertest provides an in-memory fake of the read-only Docker API
// used by StackSentry, for tests that must not depend on a Docker daemon.
package dockertest

import (
	"context"
	"errors"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"
)

// Fake implements docker.API. A non-nil error field makes the
// corresponding call fail.
type Fake struct {
	PingErr, VersionErr, InfoErr, ListErr, InspectErr, ImageErr, DiskUsageErr error

	Version    client.ServerVersionResult
	SystemInfo system.Info
	Containers []container.Summary
	Inspect    map[string]container.InspectResponse
	Images     []image.Summary
	Usage      client.DiskUsageResult

	// ImageFilters records the filters of the last ImageList call.
	ImageFilters client.Filters
	// Closed is set by Close.
	Closed bool
}

// Ping implements docker.API.
func (f *Fake) Ping(context.Context, client.PingOptions) (client.PingResult, error) {
	return client.PingResult{}, f.PingErr
}

// ServerVersion implements docker.API.
func (f *Fake) ServerVersion(context.Context, client.ServerVersionOptions) (client.ServerVersionResult, error) {
	return f.Version, f.VersionErr
}

// Info implements docker.API.
func (f *Fake) Info(context.Context, client.InfoOptions) (client.SystemInfoResult, error) {
	return client.SystemInfoResult{Info: f.SystemInfo}, f.InfoErr
}

// ContainerList implements docker.API.
func (f *Fake) ContainerList(context.Context, client.ContainerListOptions) (client.ContainerListResult, error) {
	return client.ContainerListResult{Items: f.Containers}, f.ListErr
}

// ContainerInspect implements docker.API.
func (f *Fake) ContainerInspect(_ context.Context, id string, _ client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
	if f.InspectErr != nil {
		return client.ContainerInspectResult{}, f.InspectErr
	}
	resp, ok := f.Inspect[id]
	if !ok {
		return client.ContainerInspectResult{}, errors.New("no such container: " + id)
	}
	return client.ContainerInspectResult{Container: resp}, nil
}

// ImageList implements docker.API.
func (f *Fake) ImageList(_ context.Context, opts client.ImageListOptions) (client.ImageListResult, error) {
	f.ImageFilters = opts.Filters
	return client.ImageListResult{Items: f.Images}, f.ImageErr
}

// DiskUsage implements docker.API.
func (f *Fake) DiskUsage(context.Context, client.DiskUsageOptions) (client.DiskUsageResult, error) {
	return f.Usage, f.DiskUsageErr
}

// Close implements docker.API.
func (f *Fake) Close() error {
	f.Closed = true
	return nil
}
