package composerules

import (
	"path"
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

const refVolumes = "https://docs.docker.com/engine/storage/volumes/"

func storageRules() []Rule {
	return []Rule{
		newRule(engine.Metadata{
			ID:          "SST-STO-001",
			Title:       "Database service without persistent volume",
			Category:    findings.CategoryStorage,
			Severity:    findings.SeverityHigh,
			Description: "The database service has no volume mounted at its data directory.",
			Rationale: "Without a volume the data lives in the container's writable layer and is lost when the container " +
				"is recreated, for example by docker compose down, an image upgrade or a configuration change.",
			Remediation: "Mount a named volume at the data directory, e.g. \"pgdata:/var/lib/postgresql/data\", declare it " +
				"under the top-level volumes key and back it up regularly.",
			Detection: "Known PostgreSQL, MySQL, MariaDB, MongoDB and Redis/Valkey images (official, Bitnami and common " +
				"variants) without a volume or bind mount at, above or below their data directory. PGDATA is honored for " +
				"PostgreSQL. Redis is reported as medium because it is often used as a disposable cache, and is skipped when " +
				"persistence is disabled with --save \"\".",
			Limitations: "Conservative: unknown or custom database images, volumes_from and tmpfs data directories are not " +
				"reported.",
			References: []string{refVolumes},
		}, perService(checkDatabaseVolume)),
	}
}

func checkDatabaseVolume(s *compose.Service) []engine.Issue {
	db, ref, ok := lookupDatabase(s.Image)
	if !ok {
		return nil
	}
	dataPath, ok := db.DataPaths[ref.Repository]
	if !ok {
		return nil
	}
	if db.Name == "PostgreSQL" {
		if pgdata, found := s.Env("PGDATA"); found && strings.HasPrefix(pgdata.Value, "/") {
			dataPath = path.Clean(pgdata.Value)
		}
	}
	for _, m := range s.Mounts {
		target := path.Clean(m.Target)
		// Any mount counts, including tmpfs, which is an explicit choice for
		// an ephemeral database.
		if target == dataPath || strings.HasPrefix(dataPath, target+"/") || strings.HasPrefix(target, dataPath+"/") {
			return nil
		}
	}
	if db.CacheLike && persistenceDisabled(s) {
		return nil
	}
	issue := serviceIssue(s, "no volume is mounted at "+dataPath+" ("+db.Name+" data directory)")
	issue.Remediation = "Mount a named volume at the data directory, e.g. \"" + s.Name + "-data:" + dataPath +
		"\", declare it under the top-level volumes key and back it up regularly."
	if db.CacheLike {
		issue.Severity = findings.SeverityMedium
		issue.Description = "The " + db.Name + " service has no volume at its data directory. If it is only used as a cache this may be intentional."
	}
	return one(issue)
}

// persistenceDisabled detects redis-server --save "" which turns off RDB
// snapshots and signals an intentionally ephemeral cache.
func persistenceDisabled(s *compose.Service) bool {
	tokens := commandTokens(s)
	for i, t := range tokens {
		if t != "--save" {
			continue
		}
		if i+1 >= len(tokens) {
			return true
		}
		next := tokens[i+1]
		if next == "" || next == `""` || next == "''" {
			return true
		}
	}
	return false
}
