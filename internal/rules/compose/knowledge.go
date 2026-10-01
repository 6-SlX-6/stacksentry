package composerules

import (
	"path"
	"slices"
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/imageref"
)

// database describes a well-known database or data service image.
type database struct {
	Name string
	// Repositories are matched exactly against the normalized repository.
	Repositories []string
	// DataPaths maps repositories to the container data directory. Images
	// without an entry are not checked by SST-STO-001.
	DataPaths map[string]string
	// CacheLike marks services that are often used without persistence.
	CacheLike bool
}

var databases = []database{
	{
		Name:         "PostgreSQL",
		Repositories: []string{"postgres", "postgis/postgis", "timescale/timescaledb", "pgvector/pgvector", "bitnami/postgresql"},
		DataPaths: map[string]string{
			"postgres": "/var/lib/postgresql/data", "postgis/postgis": "/var/lib/postgresql/data",
			"timescale/timescaledb": "/var/lib/postgresql/data", "pgvector/pgvector": "/var/lib/postgresql/data",
			"bitnami/postgresql": "/bitnami/postgresql",
		},
	},
	{
		Name:         "MySQL",
		Repositories: []string{"mysql", "mysql/mysql-server", "bitnami/mysql"},
		DataPaths:    map[string]string{"mysql": "/var/lib/mysql", "mysql/mysql-server": "/var/lib/mysql", "bitnami/mysql": "/bitnami/mysql"},
	},
	{
		Name:         "MariaDB",
		Repositories: []string{"mariadb", "bitnami/mariadb"},
		DataPaths:    map[string]string{"mariadb": "/var/lib/mysql", "bitnami/mariadb": "/bitnami/mariadb"},
	},
	{
		Name:         "MongoDB",
		Repositories: []string{"mongo", "mongodb/mongodb-community-server", "bitnami/mongodb"},
		DataPaths:    map[string]string{"mongo": "/data/db", "mongodb/mongodb-community-server": "/data/db", "bitnami/mongodb": "/bitnami/mongodb"},
	},
	{
		Name:         "Redis",
		Repositories: []string{"redis", "redis/redis-stack-server", "bitnami/redis", "valkey/valkey"},
		DataPaths:    map[string]string{"redis": "/data", "redis/redis-stack-server": "/data", "bitnami/redis": "/bitnami/redis/data", "valkey/valkey": "/data"},
		CacheLike:    true,
	},
	{Name: "Elasticsearch", Repositories: []string{"elasticsearch", "elasticsearch/elasticsearch", "bitnami/elasticsearch"}},
	{Name: "RabbitMQ", Repositories: []string{"rabbitmq", "bitnami/rabbitmq"}},
	{Name: "Memcached", Repositories: []string{"memcached", "bitnami/memcached"}},
	{Name: "Microsoft SQL Server", Repositories: []string{"mssql/server", "microsoft/mssql-server-linux"}},
}

// databasePorts are the default ports of common data services.
var databasePorts = map[uint32]string{
	5432:  "PostgreSQL",
	3306:  "MySQL/MariaDB",
	27017: "MongoDB",
	6379:  "Redis",
	9200:  "Elasticsearch",
	5672:  "RabbitMQ",
	11211: "Memcached",
	1433:  "Microsoft SQL Server",
}

func lookupDatabase(image string) (database, imageref.Reference, bool) {
	ref := imageref.Parse(image)
	for _, db := range databases {
		if slices.Contains(db.Repositories, ref.Repository) {
			return db, ref, true
		}
	}
	return database{}, ref, false
}

// adminTool describes an administration UI that should not be broadly
// reachable.
type adminTool struct {
	Name         string
	Repositories []string
	// DashboardPort restricts the check to one container port (Traefik's
	// API/dashboard entrypoint); zero means any published port.
	DashboardPort uint32
}

var adminTools = []adminTool{
	{Name: "Portainer", Repositories: []string{"portainer/portainer-ce", "portainer/portainer-ee", "portainer/portainer"}},
	{Name: "Traefik dashboard", Repositories: []string{"traefik"}, DashboardPort: 8080},
	{Name: "pgAdmin", Repositories: []string{"dpage/pgadmin4"}},
	{Name: "Adminer", Repositories: []string{"adminer"}},
	{Name: "Mongo Express", Repositories: []string{"mongo-express"}},
	{Name: "Grafana", Repositories: []string{"grafana/grafana", "grafana/grafana-oss", "grafana/grafana-enterprise"}},
	{Name: "Redis Commander", Repositories: []string{"rediscommander/redis-commander"}},
	{Name: "phpMyAdmin", Repositories: []string{"phpmyadmin", "phpmyadmin/phpmyadmin"}},
}

func lookupAdminTool(image string) (adminTool, bool) {
	ref := imageref.Parse(image)
	for _, tool := range adminTools {
		if slices.Contains(tool.Repositories, ref.Repository) {
			return tool, true
		}
	}
	return adminTool{}, false
}

// statefulRepositories are workflow engines, brokers and data stores that
// benefit from a graceful shutdown in addition to the databases above.
var statefulRepositories = []string{
	"n8nio/n8n", "apache/airflow", "temporalio/server", "temporalio/auto-setup", "prefecthq/prefect",
	"nodered/node-red", "kestra/kestra", "apache/kafka", "bitnami/kafka", "confluentinc/cp-kafka",
	"nats", "eclipse-mosquitto", "minio/minio", "clickhouse/clickhouse-server", "influxdb", "cassandra",
	"couchdb", "neo4j", "opensearchproject/opensearch", "bitnami/etcd", "zookeeper", "gitea/gitea",
	"nextcloud", "vaultwarden/server",
}

func isStateful(s *compose.Service) bool {
	if _, _, ok := lookupDatabase(s.Image); ok {
		return true
	}
	if slices.Contains(statefulRepositories, imageref.Parse(s.Image).Repository) {
		return true
	}
	for _, m := range s.Mounts {
		if m.Type == compose.MountVolume && m.Source != "" {
			return true
		}
	}
	return false
}

// dockerAPIImages run a Docker daemon or a Docker API proxy.
var dockerAPIImages = []string{
	"docker", "tecnativa/docker-socket-proxy", "linuxserver/socket-proxy", "wollomatic/socket-proxy",
}

func isDockerAPIService(s *compose.Service) bool {
	ref := imageref.Parse(s.Image)
	if slices.Contains(dockerAPIImages, ref.Repository) {
		return true
	}
	name := strings.ToLower(s.Name)
	for _, hint := range []string{"dind", "socket-proxy", "socketproxy", "docker-proxy", "dockerproxy", "dockerd"} {
		if strings.Contains(name, hint) {
			return true
		}
	}
	return false
}

func isDind(s *compose.Service) bool {
	ref := imageref.Parse(s.Image)
	return ref.Repository == "docker" && strings.Contains(strings.ToLower(ref.Tag), "dind")
}

// oneShotServices returns services that other services wait for with
// condition service_completed_successfully. They are expected to exit, so
// restart, healthcheck and shutdown rules do not apply to them.
func oneShotServices(p *compose.Project) map[string]bool {
	out := map[string]bool{}
	for _, s := range p.Services {
		for _, d := range s.DependsOn {
			if d.Condition == "service_completed_successfully" {
				out[d.Service] = true
			}
		}
	}
	return out
}

// cleanHostPath normalizes a bind mount source for comparisons.
func cleanHostPath(p string) string {
	if p == "" {
		return ""
	}
	return path.Clean(strings.ReplaceAll(p, "\\", "/"))
}

// isDockerSocketPath reports whether p refers to the Docker API socket or
// the Windows Docker named pipe.
func isDockerSocketPath(p string) bool {
	lower := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	return strings.HasSuffix(lower, "docker.sock") || strings.HasSuffix(lower, "pipe/docker_engine")
}

func commandTokens(s *compose.Service) []string {
	var tokens []string
	for _, part := range append(append([]string{}, s.Entrypoint...), s.Command...) {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			// Preserve empty arguments such as --save "".
			tokens = append(tokens, "")
			continue
		}
		tokens = append(tokens, fields...)
	}
	return tokens
}
