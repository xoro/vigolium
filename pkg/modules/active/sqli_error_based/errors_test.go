package sqli_error_based

import "testing"

func TestCheckBodyContainsErrorMsg_SequelizeSQLite(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantDB  string
		wantHit bool
	}{
		{
			name:    "SQLITE_ERROR colon format",
			body:    `{"message":"SQLITE_ERROR: near \"z\": syntax error"}`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "SequelizeDatabaseError",
			body:    `{"name":"SequelizeDatabaseError","message":"near \"z\": syntax error","sql":"SELECT * FROM Users WHERE email = 'admin'z'' AND password = '123'"}`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "SQLITE_ERROR bracket format (existing pattern)",
			body:    `[SQLITE_ERROR] near "z": syntax error`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "SQLAlchemy-wrapped sqlite3 OperationalError (parenthesized, no colon)",
			body:    `sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token: "'admin''" [SQL: SELECT * FROM users WHERE username = 'admin'']`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "no match",
			body:    `{"status":"ok"}`,
			wantDB:  "",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbName, _, hit := checkBodyContainsErrorMsg(tt.body)
			if hit != tt.wantHit {
				t.Errorf("hit = %v, want %v", hit, tt.wantHit)
			}
			if hit && dbName != tt.wantDB {
				t.Errorf("dbName = %q, want %q", dbName, tt.wantDB)
			}
		})
	}
}

// TestCheckBodyContainsErrorMsg_TiDBBoundaries pins the tightened TiDB patterns:
// the short "TiKV" token must still match a genuine error leak but must NOT match
// when it is glued inside a base64/hex blob (e.g. a Cloudflare challenge page's
// random per-request tokens), which is the noise that drove the original false
// positive.
func TestCheckBodyContainsErrorMsg_TiDBBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantHit bool
	}{
		{
			name:    "genuine TiKV error leak matches",
			body:    `ERROR 9005 (HY000): Region is unavailable: TiKV server is busy`,
			wantHit: true,
		},
		{
			name:    "TiDB server phrase matches",
			body:    `{"error":"TiDB server timeout, please retry"}`,
			wantHit: true,
		},
		{
			name:    "TiKV glued inside a base64 blob does not match",
			body:    `md: 'p1B_grnutDRoRTiKV6QwS.iHHlCgBWTBsSTzYs.id2UyL3g'`,
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbName, _, hit := checkBodyContainsErrorMsg(tt.body)
			if hit != tt.wantHit {
				t.Errorf("hit = %v, want %v (db=%q)", hit, tt.wantHit, dbName)
			}
			if hit && dbName != "TiDB" {
				t.Errorf("dbName = %q, want %q", dbName, "TiDB")
			}
		})
	}
}

// TestCheckBodyContainsErrorMsg_CockroachBoundaries pins the tightened CockroachDB
// patterns: the bare "CockroachDB" token must still match a genuine error leak but
// must NOT match when it is glued inside ordinary page content — the motivating
// false positive was a Salesforce community 404 shell whose inline feature-flag
// list carried "...userHasCockroachDBEnabled...".
func TestCheckBodyContainsErrorMsg_CockroachBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantHit bool
	}{
		{
			name:    "standalone CockroachDB error matches",
			body:    `pq: syntax error at or near ")" (CockroachDB v23.1)`,
			wantHit: true,
		},
		{
			name:    "crdb_internal reference matches",
			body:    `ERROR: relation "crdb_internal.zones" does not exist`,
			wantHit: true,
		},
		{
			name:    "node-readiness error matches",
			body:    `node is not ready to accept SQL clients`,
			wantHit: true,
		},
		{
			name:    "CockroachDB glued inside a feature-flag name does not match",
			body:    `"UnifiedAnalytics.userHasCockroachDBEnabled":false,"x":1`,
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbName, _, hit := checkBodyContainsErrorMsg(tt.body)
			if hit != tt.wantHit {
				t.Errorf("hit = %v, want %v (db=%q)", hit, tt.wantHit, dbName)
			}
			if hit && dbName != "CockroachDB" {
				t.Errorf("dbName = %q, want %q", dbName, "CockroachDB")
			}
		})
	}
}
