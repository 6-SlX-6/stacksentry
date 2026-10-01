package composerules

import "testing"

func TestRES001MemoryLimit(t *testing.T) {
	runRuleCases(t, "SST-RES-001", []ruleCase{
		{"missing", svc("image: x:1"), []want{{"app", low, []string{"memory and mem_limit are not set"}}}},
		{"deploy limit", svc("image: x:1\ndeploy:\n  resources:\n    limits:\n      memory: 512M"), nil},
		{"mem_limit", svc("image: x:1\nmem_limit: 1g"), nil},
		{"reservation only", svc("image: x:1\ndeploy:\n  resources:\n    reservations:\n      memory: 128M"), []want{{"app", low, nil}}},
	})
}

func TestRES002CPULimit(t *testing.T) {
	runRuleCases(t, "SST-RES-002", []ruleCase{
		{"missing", svc("image: x:1"), []want{{"app", low, []string{"cpus and cpus are not set"}}}},
		{"deploy limit", svc("image: x:1\ndeploy:\n  resources:\n    limits:\n      cpus: \"0.5\""), nil},
		{"cpus", svc("image: x:1\ncpus: 1.5"), nil},
		{"cpu quota", svc("image: x:1\ncpu_quota: 50000"), nil},
	})
}

func TestRES003LogRotation(t *testing.T) {
	runRuleCases(t, "SST-RES-003", []ruleCase{
		{"no logging section", svc("image: x:1"), []want{{"app", med, []string{"logging is not configured"}}}},
		{"json-file without max-size", svc("image: x:1\nlogging:\n  driver: json-file\n  options:\n    max-file: \"3\""), []want{{"app", med, []string{"json-file without options.max-size"}}}},
		{"options without driver", svc("image: x:1\nlogging:\n  options:\n    max-file: \"3\""), []want{{"app", med, nil}}},
		{"json-file with rotation", svc("image: x:1\nlogging:\n  driver: json-file\n  options:\n    max-size: 10m\n    max-file: \"3\""), nil},
		{"max-size only is bounded", svc("image: x:1\nlogging:\n  options:\n    max-size: 10m"), nil},
		{"local driver", svc("image: x:1\nlogging:\n  driver: local"), nil},
		{"journald", svc("image: x:1\nlogging:\n  driver: journald"), nil},
		{"plugin driver", svc("image: x:1\nlogging:\n  driver: grafana/loki-docker-driver:latest"), nil},
	})
}
