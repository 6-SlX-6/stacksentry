package composerules

import "testing"

func TestSTO001DatabaseVolume(t *testing.T) {
	runRuleCases(t, "SST-STO-001", []ruleCase{
		{"postgres without volume", svc("image: postgres:16"), []want{{"app", high, []string{"no volume is mounted at /var/lib/postgresql/data (PostgreSQL data directory)"}}}},
		{"postgres named volume", svc("image: postgres:16\nvolumes:\n  - pgdata:/var/lib/postgresql/data") + "volumes:\n  pgdata:\n", nil},
		{"postgres 18 parent mount", svc("image: postgres:18\nvolumes:\n  - pgdata:/var/lib/postgresql") + "volumes:\n  pgdata:\n", nil},
		{"postgres bind mount", svc("image: postgres:16\nvolumes:\n  - ./pg:/var/lib/postgresql/data"), nil},
		{"custom PGDATA without volume", svc("image: postgres:16\nenvironment:\n  PGDATA: /pgdata\nvolumes:\n  - other:/var/lib/postgresql/data") + "volumes:\n  other:\n",
			[]want{{"app", high, []string{"/pgdata"}}}},
		{"custom PGDATA with volume", svc("image: postgres:16\nenvironment:\n  PGDATA: /pgdata/data\nvolumes:\n  - pg:/pgdata") + "volumes:\n  pg:\n", nil},
		{"bitnami postgres", svc("image: bitnami/postgresql:16"), []want{{"app", high, []string{"/bitnami/postgresql"}}}},
		{"mysql and mariadb", "services:\n  my:\n    image: mysql:8.4\n  maria:\n    image: mariadb:11\n",
			[]want{{"my", high, []string{"/var/lib/mysql"}}, {"maria", high, []string{"/var/lib/mysql"}}}},
		{"mongo", svc("image: mongo:7"), []want{{"app", high, []string{"/data/db"}}}},
		{"mongo with volume", svc("image: mongo:7\nvolumes:\n  - mongo:/data/db") + "volumes:\n  mongo:\n", nil},
		{"redis is medium", svc("image: redis:7"), []want{{"app", med, []string{"/data"}}}},
		{"redis cache without persistence", svc("image: redis:7\ncommand: [\"redis-server\", \"--save\", \"\", \"--appendonly\", \"no\"]"), nil},
		{"redis shell form without persistence", svc("image: redis:7\ncommand: redis-server --save \"\""), nil},
		{"tmpfs data dir is intentional", svc("image: postgres:16\ntmpfs:\n  - /var/lib/postgresql/data"), nil},
		{"unknown image is not reported", svc("image: mycorp/postgres-custom:1"), nil},
		{"elasticsearch has no data path check", svc("image: elasticsearch:8.15.0"), nil},
	})
}

func TestSTO001RemediationUsesDataPath(t *testing.T) {
	got := runRule(t, "SST-STO-001", loadYAML(t, "services:\n  cache:\n    image: redis:7\n"))
	if len(got) != 1 || got[0].Remediation != "Mount a named volume at the data directory, e.g. \"cache-data:/data\", declare it under the top-level volumes key and back it up regularly." {
		t.Fatalf("remediation = %q", got[0].Remediation)
	}
}
