package composerules

import "testing"

func TestNET001DatabasePorts(t *testing.T) {
	runRuleCases(t, "SST-NET-001", []ruleCase{
		{"short syntax all interfaces", svc("image: postgres:16\nports:\n  - \"5432:5432\""),
			[]want{{"app", high, []string{"5432:5432/tcp (PostgreSQL port published on all host interfaces)"}}}},
		{"explicit 0.0.0.0", svc("image: mysql:8\nports:\n  - \"0.0.0.0:3306:3306\""), []want{{"app", high, []string{"0.0.0.0:3306:3306"}}}},
		{"loopback is low", svc("image: postgres:16\nports:\n  - \"127.0.0.1:5432:5432\""), []want{{"app", low, []string{"localhost only"}}}},
		{"ipv6 loopback is low", svc("image: redis:7\nports:\n  - \"[::1]:6379:6379\""), []want{{"app", low, nil}}},
		{"specific interface is medium", svc("image: mongo:7\nports:\n  - \"192.168.1.10:27017:27017\""), []want{{"app", med, []string{"specific host interface"}}}},
		{"random host port", svc("image: redis:7\nports:\n  - \"6379\""), []want{{"app", high, []string{"random host port"}}}},
		{"port number on unknown image", svc("image: custom/store:1\nports:\n  - \"9200:9200\"\n  - \"11211:11211\""),
			[]want{{"app", high, []string{"Memcached"}}, {"app", high, []string{"Elasticsearch"}}}},
		{"database image on custom port", svc("image: postgres:16\nports:\n  - \"15432:5433\""), []want{{"app", high, []string{"PostgreSQL"}}}},
		{"long syntax", svc("image: x:1\nports:\n  - target: 1433\n    published: \"1433\"\n    host_ip: 127.0.0.1"), []want{{"app", low, nil}}},
		{"each listed port", "services:\n  a:\n    image: x:1\n    ports: [\"5672:5672\"]\n  b:\n    image: x:1\n    ports: [\"3306:3306\"]\n",
			[]want{{"a", high, []string{"RabbitMQ"}}, {"b", high, []string{"MySQL/MariaDB"}}}},
		{"web port is fine", svc("image: nginx:1.27\nports:\n  - \"80:80\""), nil},
		{"expose is not published", svc("image: postgres:16\nexpose: [\"5432\"]"), nil},
		{"host network ports ignored", svc("image: postgres:16\nnetwork_mode: host"), nil},
	})
}

const tieredStack = `services:
  web:
    image: nginx:1.27
    ports: ["80:80"]
  api:
    image: app:1
  db:
    image: postgres:16
`

func TestNET002Segmentation(t *testing.T) {
	runRuleCases(t, "SST-NET-002", []ruleCase{
		{"flat tiered stack", "name: shop\n" + tieredStack,
			[]want{{"shop", low, []string{"all 3 services use only the default network", "data services: db", "services with published ports: web"}}}},
		{"explicit networks", "name: shop\n" + tieredStack + "    networks: [backend]\nnetworks:\n  backend:\n", nil},
		{"too small", "services:\n  web:\n    image: nginx:1.27\n    ports: [\"80:80\"]\n  db:\n    image: postgres:16\n", nil},
		{"no database", "services:\n  a:\n    image: nginx:1.27\n    ports: [\"80:80\"]\n  b:\n    image: x:1\n  c:\n    image: y:1\n", nil},
		{"nothing published", "services:\n  a:\n    image: x:1\n  b:\n    image: y:1\n  db:\n    image: postgres:16\n", nil},
		{"network_mode in use", "services:\n  a:\n    image: nginx:1.27\n    ports: [\"80:80\"]\n  b:\n    image: x:1\n    network_mode: \"service:a\"\n  db:\n    image: postgres:16\n", nil},
	})
}

func TestNET003AdminInterfaces(t *testing.T) {
	runRuleCases(t, "SST-NET-003", []ruleCase{
		{"portainer", svc("image: portainer/portainer-ce:2.21.4\nports:\n  - \"9443:9443\""),
			[]want{{"app", med, []string{"portainer/portainer-ce:2.21.4 publishes 9443:9443/tcp on all host interfaces (Portainer)"}}}},
		{"pgadmin", svc("image: dpage/pgadmin4:8\nports:\n  - \"5050:80\""), []want{{"app", med, []string{"pgAdmin"}}}},
		{"each admin tool", "services:\n  a:\n    image: adminer:4\n    ports: [\"8080:8080\"]\n  b:\n    image: mongo-express:1\n    ports: [\"8081:8081\"]\n  c:\n    image: grafana/grafana:11.2.0\n    ports: [\"3000:3000\"]\n  d:\n    image: rediscommander/redis-commander:latest\n    ports: [\"8082:8081\"]\n  e:\n    image: phpmyadmin:5\n    ports: [\"8083:80\"]\n",
			[]want{{"a", med, []string{"Adminer"}}, {"b", med, []string{"Mongo Express"}}, {"c", med, []string{"Grafana"}}, {"d", med, []string{"Redis Commander"}}, {"e", med, []string{"phpMyAdmin"}}}},
		{"traefik dashboard port", svc("image: traefik:v3.1\nports:\n  - \"80:80\"\n  - \"8080:8080\""), []want{{"app", med, []string{"8080:8080/tcp", "Traefik dashboard"}}}},
		{"traefik without dashboard port", svc("image: traefik:v3.1\nports:\n  - \"80:80\"\n  - \"443:443\""), nil},
		{"loopback is fine", svc("image: portainer/portainer-ce:2.21.4\nports:\n  - \"127.0.0.1:9443:9443\""), nil},
		{"specific interface is fine", svc("image: grafana/grafana:11.2.0\nports:\n  - \"10.0.0.2:3000:3000\""), nil},
		{"not published", svc("image: grafana/grafana:11.2.0"), nil},
	})
}
