// Package docker inspects a local Docker daemon through the official Docker
// Engine API client. It only uses read-only API endpoints and never changes
// containers, images, networks, volumes or daemon configuration.
package docker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

// API is the read-only subset of the Docker Engine API used by StackSentry.
// *client.Client satisfies it; tests provide fakes.
type API interface {
	Ping(ctx context.Context, options client.PingOptions) (client.PingResult, error)
	ServerVersion(ctx context.Context, options client.ServerVersionOptions) (client.ServerVersionResult, error)
	Info(ctx context.Context, options client.InfoOptions) (client.SystemInfoResult, error)
	ContainerList(ctx context.Context, options client.ContainerListOptions) (client.ContainerListResult, error)
	ContainerInspect(ctx context.Context, id string, options client.ContainerInspectOptions) (client.ContainerInspectResult, error)
	ImageList(ctx context.Context, options client.ImageListOptions) (client.ImageListResult, error)
	DiskUsage(ctx context.Context, options client.DiskUsageOptions) (client.DiskUsageResult, error)
	Close() error
}

// Connection is an established, verified connection to a Docker daemon.
type Connection struct {
	API API
	// Endpoint is the daemon address, e.g. unix:///var/run/docker.sock.
	Endpoint string
	// TLS reports whether the client was configured with TLS certificates.
	TLS bool
}

// PingTimeout bounds how long Connect waits for the daemon to answer.
const PingTimeout = 10 * time.Second

// Connect creates a client from the standard Docker environment variables
// (DOCKER_HOST, DOCKER_API_VERSION, DOCKER_CERT_PATH, DOCKER_TLS_VERIFY) and
// verifies that the daemon answers. Docker CLI contexts are not consulted.
func Connect(ctx context.Context) (*Connection, error) {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		endpoint := os.Getenv("DOCKER_HOST")
		return nil, &UnavailableError{Endpoint: endpoint, Reason: "invalid Docker client configuration: " + err.Error(),
			Hint: "Check the DOCKER_HOST, DOCKER_API_VERSION and DOCKER_CERT_PATH environment variables.", Err: err}
	}
	conn := &Connection{API: cli, Endpoint: cli.DaemonHost(), TLS: os.Getenv("DOCKER_CERT_PATH") != ""}
	if err := Verify(ctx, conn); err != nil {
		_ = cli.Close()
		return nil, err
	}
	return conn, nil
}

// Verify pings the daemon and converts failures into an UnavailableError.
func Verify(ctx context.Context, conn *Connection) error {
	pingCtx, cancel := context.WithTimeout(ctx, PingTimeout)
	defer cancel()
	if _, err := conn.API.Ping(pingCtx, client.PingOptions{}); err != nil {
		return Classify(conn.Endpoint, err)
	}
	return nil
}

// UnavailableError explains why the Docker daemon could not be used. It is
// a user-environment problem and maps to exit code 2.
type UnavailableError struct {
	Endpoint string
	Reason   string
	Hint     string
	Err      error
}

// Error implements error.
func (e *UnavailableError) Error() string {
	endpoint := e.Endpoint
	if endpoint == "" {
		endpoint = "the default endpoint"
	}
	msg := fmt.Sprintf("cannot use the Docker daemon at %s: %s", endpoint, e.Reason)
	if e.Hint != "" {
		msg += ". " + e.Hint
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *UnavailableError) Unwrap() error { return e.Err }

// Classify turns a connection error into an actionable UnavailableError.
func Classify(endpoint string, err error) *UnavailableError {
	msg := strings.ToLower(err.Error())
	ue := &UnavailableError{Endpoint: endpoint, Err: err}
	switch {
	case errors.Is(err, fs.ErrPermission) || strings.Contains(msg, "permission denied"):
		ue.Reason = "permission denied"
		ue.Hint = "Your user may not access the Docker socket. Run StackSentry as a user that can run \"docker info\" " +
			"(membership in the docker group is root-equivalent), or set DOCKER_HOST."
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		ue.Reason = "the daemon did not respond in time"
		ue.Hint = "Check that the Docker daemon is healthy and that DOCKER_HOST points to the right endpoint."
	case client.IsErrConnectionFailed(err) || strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such file") || strings.Contains(msg, "cannot find the file"):
		ue.Reason = "the daemon is not reachable"
		ue.Hint = "Is Docker installed and running? Set DOCKER_HOST if the daemon listens on a non-default endpoint."
	default:
		ue.Reason = err.Error()
	}
	return ue
}
