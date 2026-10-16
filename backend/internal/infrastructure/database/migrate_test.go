package database

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadMigrationsEmbedded(t *testing.T) {
	ms, err := LoadMigrations()
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	if len(ms) == 0 || ms[0].Version != 1 {
		t.Fatalf("expected migrations starting at 0001, got %+v", ms)
	}
}

func TestLoadMigrationsValidation(t *testing.T) {
	cases := []struct {
		name    string
		files   fstest.MapFS
		wantErr string
	}{
		{"gap", fstest.MapFS{
			"m/0001_a.sql": {Data: []byte("SELECT 1")},
			"m/0003_c.sql": {Data: []byte("SELECT 1")},
		}, "contiguous"},
		{"bad name", fstest.MapFS{"m/init.sql": {Data: []byte("SELECT 1")}}, "NNNN_name.sql"},
		{"duplicate version", fstest.MapFS{
			"m/0001_a.sql": {Data: []byte("SELECT 1")},
			"m/0001_b.sql": {Data: []byte("SELECT 1")},
		}, "contiguous"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadMigrationsFrom(tc.files, "m")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// Static guard on the schema: every append-only table must have both the row
// trigger and the TRUNCATE trigger. Dropping one would silently break
// FR-SEC-001 / FR-SEC-031 immutability.
func TestInitMigrationProtectsAppendOnlyTables(t *testing.T) {
	ms, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	sql := ms[0].SQL
	for _, table := range []string{"raw_logs", "audit_logs", "batch_logs", "incident_comments", "alert_deliveries"} {
		row := "BEFORE UPDATE OR DELETE ON " + table
		trunc := "BEFORE TRUNCATE ON " + table
		if !strings.Contains(sql, row) || !strings.Contains(sql, trunc) {
			t.Errorf("%s is missing an immutability trigger", table)
		}
	}
}

// The CHECK constraints must use the same enum strings as the domain/frontend.
func TestInitMigrationEnumStrings(t *testing.T) {
	ms, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	sql := ms[0].SQL
	for _, want := range []string{
		"'Login Success', 'Login Failed', 'Privilege Escalation'",
		"'Low', 'Medium', 'High', 'Critical'",
		"'Open', 'Acknowledged', 'Resolved'",
		"'admin', 'analyst', 'viewer'",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("0001_init.sql missing enum list %s", want)
		}
	}
}
