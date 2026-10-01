package docker

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/findings"
)

// UnencryptedAPIPort is the conventional port of the unencrypted Docker API.
const UnencryptedAPIPort = 2375

// listenerProbe looks for Docker daemon TCP listeners. Besides the Docker
// API it reads, on Linux and for a local daemon only, /etc/docker/daemon.json,
// the dockerd command line in /proc and the kernel's TCP socket tables. All
// sources are optional; anything that cannot be read becomes a limitation.
type listenerProbe struct {
	fsys     fs.FS
	goos     string
	endpoint string
	tls      bool
}

var apiWarning = regexp.MustCompile(`API is accessible on (\S+?)(?:\s|$)`)

func (p listenerProbe) run(warnings []string, limitations []string) ([]ListenerObservation, []string) {
	var obs []ListenerObservation
	for _, w := range warnings {
		if m := apiWarning.FindStringSubmatch(w); m != nil {
			obs = append(obs, ListenerObservation{Source: "Docker API (docker info warnings)", Address: m[1],
				Detail: "the daemon reports that its API is accessible without encryption", Confidence: findings.ConfidenceHigh})
		}
	}
	if strings.HasPrefix(p.endpoint, "tcp://") && !p.tls {
		obs = append(obs, ListenerObservation{Source: "StackSentry connection (DOCKER_HOST)", Address: p.endpoint,
			Detail: "StackSentry reached the daemon over TCP without TLS", Confidence: findings.ConfidenceHigh})
	}

	local := strings.HasPrefix(p.endpoint, "unix://") || strings.HasPrefix(p.endpoint, "npipe://")
	switch {
	case !local:
		limitations = append(limitations, "The Docker daemon is not local, so daemon.json and active listeners on the daemon host were not inspected.")
		return obs, limitations
	case p.goos != "linux":
		limitations = append(limitations, fmt.Sprintf("Daemon configuration files and active TCP listeners are only inspected on Linux; on %s only the Docker API and the connection settings were checked.", p.goos))
		return obs, limitations
	case p.fsys == nil:
		limitations = append(limitations, "Host filesystem inspection is disabled; daemon.json and active listeners were not inspected.")
		return obs, limitations
	}

	o, l := p.daemonJSON()
	obs, limitations = append(obs, o...), append(limitations, l...)
	o, l = p.dockerdCmdline()
	obs, limitations = append(obs, o...), append(limitations, l...)
	o, l = p.socketTables()
	obs, limitations = append(obs, o...), append(limitations, l...)
	return obs, limitations
}

func (p listenerProbe) daemonJSON() ([]ListenerObservation, []string) {
	data, err := fs.ReadFile(p.fsys, "etc/docker/daemon.json")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, []string{"/etc/docker/daemon.json could not be read (" + reason(err) + "); configured listeners were not checked."}
	}
	var cfg struct {
		Hosts     []string `json:"hosts"`
		TLSVerify *bool    `json:"tlsverify"`
		TLS       *bool    `json:"tls"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, []string{"/etc/docker/daemon.json is not valid JSON; configured listeners were not checked."}
	}
	verify := cfg.TLSVerify != nil && *cfg.TLSVerify
	tls := cfg.TLS != nil && *cfg.TLS
	return tcpObservations(cfg.Hosts, verify, tls, "/etc/docker/daemon.json (hosts)"), nil
}

func (p listenerProbe) dockerdCmdline() ([]ListenerObservation, []string) {
	entries, err := fs.ReadDir(p.fsys, "proc")
	if err != nil {
		return nil, []string{"/proc could not be read (" + reason(err) + "); the dockerd command line was not checked."}
	}
	found, unreadable := false, false
	var obs []ListenerObservation
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm, err := fs.ReadFile(p.fsys, "proc/"+e.Name()+"/comm")
		if err != nil || strings.TrimSpace(string(comm)) != "dockerd" {
			continue
		}
		found = true
		raw, err := fs.ReadFile(p.fsys, "proc/"+e.Name()+"/cmdline")
		if err != nil {
			unreadable = true
			continue
		}
		hosts, verify, tls := parseDaemonArgs(strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00"))
		obs = append(obs, tcpObservations(hosts, verify, tls, "dockerd command line (pid "+e.Name()+")")...)
	}
	switch {
	case !found:
		return obs, []string{"No dockerd process is visible in /proc (for example rootless Docker in another namespace, Docker Desktop, or restricted /proc); its command line was not checked."}
	case unreadable:
		return obs, []string{"The dockerd command line could not be read; listeners configured with -H were not checked."}
	}
	return obs, nil
}

// parseDaemonArgs extracts -H/--host values and TLS flags from dockerd's
// arguments.
func parseDaemonArgs(args []string) (hosts []string, verify, tls bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "-H" || a == "--host") && i+1 < len(args):
			hosts = append(hosts, args[i+1])
			i++
		case strings.HasPrefix(a, "--host="):
			hosts = append(hosts, strings.TrimPrefix(a, "--host="))
		case strings.HasPrefix(a, "-H") && len(a) > 2:
			hosts = append(hosts, strings.TrimPrefix(strings.TrimPrefix(a, "-H"), "="))
		case a == "--tlsverify" || a == "--tlsverify=true":
			verify = true
		case a == "--tls" || a == "--tls=true":
			tls = true
		}
	}
	return hosts, verify, tls
}

func tcpObservations(hosts []string, verify, tls bool, source string) []ListenerObservation {
	if verify {
		return nil
	}
	var obs []ListenerObservation
	for _, h := range hosts {
		if !strings.HasPrefix(h, "tcp://") {
			continue
		}
		detail := "TCP listener without TLS"
		if tls {
			detail = "TCP listener with TLS but without client certificate verification (--tlsverify)"
		}
		obs = append(obs, ListenerObservation{Source: source, Address: h, Detail: detail, Confidence: findings.ConfidenceHigh})
	}
	return obs
}

// socketTables reports sockets listening on port 2375 using the kernel's
// /proc/net/tcp tables. The owning process is not identified, so these
// observations have medium confidence.
func (p listenerProbe) socketTables() ([]ListenerObservation, []string) {
	var obs []ListenerObservation
	var limitations []string
	for _, table := range []string{"proc/net/tcp", "proc/net/tcp6"} {
		data, err := fs.ReadFile(p.fsys, table)
		if errors.Is(err, fs.ErrNotExist) && strings.HasSuffix(table, "6") {
			continue // IPv6 disabled
		}
		if err != nil {
			limitations = append(limitations, "/"+table+" could not be read ("+reason(err)+"); active listeners were not checked.")
			continue
		}
		for _, addr := range listeningOn(data, UnencryptedAPIPort) {
			obs = append(obs, ListenerObservation{Source: "/" + table, Address: "tcp://" + addr,
				Detail: "a process listens on the unencrypted Docker API port 2375", Confidence: findings.ConfidenceMedium})
		}
	}
	return obs, limitations
}

// listeningOn parses a /proc/net/tcp table and returns the local addresses
// of sockets in LISTEN state on port.
func listeningOn(table []byte, port int) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(table))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		host, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || int(p) != port {
			continue
		}
		ip := decodeProcIP(host)
		if ip == nil {
			continue
		}
		out = append(out, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}
	return out
}

// decodeProcIP decodes the hexadecimal, host-byte-order (little endian on
// all platforms Docker supports) addresses used in /proc/net/tcp*.
func decodeProcIP(s string) net.IP {
	b, err := hex.DecodeString(s)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil
	}
	ip := make(net.IP, len(b))
	for i := 0; i < len(b); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return ip
}

func reason(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "permission denied"
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// ListenerExposure classifies a listener address: true when it is
// reachable only from the local machine.
func ListenerExposure(address string) (loopbackOnly bool) {
	rest := address
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/"); i >= 0 {
		rest = rest[:i]
	}
	host, _, err := net.SplitHostPort(rest)
	if err != nil {
		host = rest
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
