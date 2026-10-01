package composerules

import "testing"

func TestOPS001NoHealthcheck(t *testing.T) {
	runRuleCases(t, "SST-OPS-001", []ruleCase{
		{"missing", svc("image: x:1"), []want{{"app", med, []string{"healthcheck is not defined"}}}},
		{"defined", svc("image: x:1\nhealthcheck:\n  test: [\"CMD\", \"true\"]"), nil},
		{"disabled is left to OPS-002", svc("image: x:1\nhealthcheck:\n  disable: true"), nil},
		{"one-shot job is skipped", "services:\n  migrate:\n    image: app:1\n  app:\n    image: app:1\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n    depends_on:\n      migrate:\n        condition: service_completed_successfully\n", nil},
		{"regular dependency is not one-shot", "services:\n  db:\n    image: postgres:16\n  app:\n    image: app:1\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n    depends_on:\n      db:\n        condition: service_started\n",
			[]want{{"db", med, nil}}},
	})
}

func TestOPS002HealthcheckDisabled(t *testing.T) {
	runRuleCases(t, "SST-OPS-002", []ruleCase{
		{"disable true", svc("image: x:1\nhealthcheck:\n  disable: true"), []want{{"app", med, []string{"healthcheck is disabled"}}}},
		{"test NONE", svc("image: x:1\nhealthcheck:\n  test: [\"NONE\"]"), []want{{"app", med, nil}}},
		{"enabled", svc("image: x:1\nhealthcheck:\n  test: [\"CMD-SHELL\", \"curl -f http://localhost\"]"), nil},
		{"missing", svc("image: x:1"), nil},
	})
}

func TestOPS003RestartPolicy(t *testing.T) {
	runRuleCases(t, "SST-OPS-003", []ruleCase{
		{"missing", svc("image: x:1"), []want{{"app", high, []string{"restart is missing"}}}},
		{"unless-stopped", svc("image: x:1\nrestart: unless-stopped"), nil},
		{"always", svc("image: x:1\nrestart: always"), nil},
		{"on-failure with retries", svc("image: x:1\nrestart: on-failure:3"), nil},
		{"deploy restart policy", svc("image: x:1\ndeploy:\n  restart_policy:\n    condition: on-failure"), nil},
		{"explicit no", svc("image: x:1\nrestart: \"no\""), []want{{"app", low, []string{"restart: \"no\""}}}},
		{"explicit no on long-running service", svc("image: nginx:1.27\nrestart: \"no\"\nports:\n  - \"8080:80\""), []want{{"app", med, nil}}},
		{"explicit no on database", svc("image: postgres:16\nrestart: \"no\""), []want{{"app", med, nil}}},
		{"deploy condition none", svc("image: x:1\ndeploy:\n  restart_policy:\n    condition: none"), []want{{"app", low, []string{"condition: none"}}}},
		{"one-shot job is skipped", "services:\n  init:\n    image: busybox:1.36\n  app:\n    image: app:1\n    restart: always\n    depends_on:\n      init:\n        condition: service_completed_successfully\n", nil},
	})
}

func TestOPS004ContainerName(t *testing.T) {
	runRuleCases(t, "SST-OPS-004", []ruleCase{
		{"set", svc("image: x:1\ncontainer_name: my-app"), []want{{"app", low, []string{"container_name: my-app"}}}},
		{"unset", svc("image: x:1"), nil},
	})
}

func TestOPS005MutableTag(t *testing.T) {
	runRuleCases(t, "SST-OPS-005", []ruleCase{
		{"latest", svc("image: nginx:latest"), []want{{"app", med, []string{"image: nginx:latest"}}}},
		{"untagged", svc("image: nginx"), []want{{"app", med, []string{"no tag, resolves to latest"}}}},
		{"registry with port and no tag", svc("image: registry.local:5000/team/app"), []want{{"app", med, nil}}},
		{"channel tag", svc("image: app:stable"), []want{{"app", low, []string{"image: app:stable"}}}},
		{"main branch tag", svc("image: ghcr.io/org/app:main"), []want{{"app", low, nil}}},
		{"semver", svc("image: app:1.2.3"), nil},
		{"major only", svc("image: postgres:16"), nil},
		{"version with variant", svc("image: nginx:1.27-alpine"), nil},
		{"latest pinned by digest", svc("image: nginx:latest@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), nil},
		{"build is skipped", svc("build: .\nimage: myapp:latest"), nil},
	})
}

func TestOPS006DigestNotPinned(t *testing.T) {
	runRuleCases(t, "SST-OPS-006", []ruleCase{
		{"version tag", svc("image: postgres:16.4"), []want{{"app", low, []string{"postgres:16.4 has no @sha256 digest"}}}},
		{"digest pinned", svc("image: postgres:16.4@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), nil},
		{"latest left to OPS-005", svc("image: postgres:latest"), nil},
		{"untagged left to OPS-005", svc("image: postgres"), nil},
		{"channel left to OPS-005", svc("image: postgres:alpine"), nil},
		{"build is skipped", svc("build:\n  context: .\nimage: myapp:1.0"), nil},
	})
}

func TestOPS007StopGracePeriod(t *testing.T) {
	runRuleCases(t, "SST-OPS-007", []ruleCase{
		{"database is low", svc("image: postgres:16"), []want{{"app", low, []string{"stop_grace_period is not set"}}}},
		{"workflow tool is low", svc("image: n8nio/n8n:1.64.0"), []want{{"app", low, nil}}},
		{"named volume makes it stateful", svc("image: x:1\nvolumes:\n  - data:/data") + "volumes:\n  data:\n", []want{{"app", low, nil}}},
		{"stateless is info", svc("image: nginx:1.27"), []want{{"app", info, nil}}},
		{"set", svc("image: postgres:16\nstop_grace_period: 1m"), nil},
		{"one-shot job is skipped", "services:\n  seed:\n    image: postgres:16\n  app:\n    image: x:1\n    stop_grace_period: 5s\n    depends_on:\n      seed:\n        condition: service_completed_successfully\n", nil},
	})
}
