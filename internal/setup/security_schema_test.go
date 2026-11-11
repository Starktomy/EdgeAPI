package setup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeaOSLab/EdgeAPI/internal/statbatches"
	"github.com/go-sql-driver/mysql"
	"github.com/iwind/TeaGo/dbs"
)

func TestSecuritySchemaMigratesPasswordsAndTrafficReceipts(t *testing.T) {
	dsn := os.Getenv("EDGE_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set EDGE_TEST_MYSQL_DSN to a disposable MySQL database")
	}
	db, err := dbs.NewInstanceFromConfig(&dbs.DBConfig{Driver: "mysql", Dsn: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var schema SQLDumpResult
	if err := json.Unmarshal(sqlData, &schema); err != nil {
		t.Fatal(err)
	}
	admins, receipts := schema.FindTable("edgeAdmins"), schema.FindTable("edgeTrafficBatchReceipts")
	if admins == nil || receipts == nil || receipts.FindField("applied") == nil {
		t.Fatal("production schema omits security migration fields")
	}
	// Unique fixture names allow this test to share the disposable database
	// with the receipt retry test without changing application tables.
	oldName := admins.Name
	admins.Name = "edgeSecuritySchemaAdminsFixture"
	admins.Definition = strings.ReplaceAll(admins.Definition, oldName, admins.Name)
	oldName = receipts.Name
	receipts.Name = "edgeSecuritySchemaReceiptsFixture"
	receipts.Definition = strings.ReplaceAll(receipts.Definition, oldName, receipts.Name)
	for _, table := range []*SQLTable{admins, receipts} {
		_, _ = db.Exec("DROP TABLE IF EXISTS " + table.Name)
		defer db.Exec("DROP TABLE IF EXISTS " + table.Name)
	}
	if _, err := db.Exec("CREATE TABLE " + admins.Name + " (id int unsigned NOT NULL AUTO_INCREMENT, username varchar(64), password varchar(32), PRIMARY KEY(id), KEY password(password)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); err != nil {
		t.Fatal(err)
	}
	dump := NewSQLDump()
	for pass := 0; pass < 2; pass++ {
		queue := make(chan *sqlItem, 16)
		if _, err := dump.applyQueue(db, &SQLDumpResult{Tables: []*SQLTable{admins, receipts}}, false, queue); err != nil {
			t.Fatal(err)
		}
		close(queue)
		for item := range queue {
			if _, err := db.Exec(item.sqlString, item.args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	password := "$argon2id$v=19$m=19456,t=2,p=1$" + strings.Repeat("a", 70)
	if _, err := db.Exec("INSERT INTO "+admins.Name+" (username,password) VALUES (?,?)", "fixture", password); err != nil {
		t.Fatal("expanded password column cannot store Argon2id:", err)
	}
	var stored string
	if err := db.Raw().QueryRow("SELECT password FROM " + admins.Name + " WHERE username='fixture'").Scan(&stored); err != nil || stored != password {
		t.Fatalf("password hash was truncated: %v", err)
	}
	if _, err := db.Exec("INSERT INTO "+receipts.Name+" (role,nodeId,batchId,payloadSHA,createdAt) VALUES ('node',1,?, ?, UNIX_TIMESTAMP())", strings.Repeat("a", 32), strings.Repeat("b", 64)); err != nil {
		t.Fatal("migrated receipt schema cannot accept a batch:", err)
	}
}

func TestSecuritySchemaBackportSerializesStartupsAndPreservesReceipts(t *testing.T) {
	dsn := os.Getenv("EDGE_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set EDGE_TEST_MYSQL_DSN to a disposable MySQL database")
	}
	db, err := dbs.NewInstanceFromConfig(&dbs.DBConfig{Driver: "mysql", Dsn: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, query := range []string{
		"DROP TABLE IF EXISTS edgeAdmins",
		"CREATE TABLE edgeAdmins (id int PRIMARY KEY, password varchar(32), KEY password(password)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
		"DROP TABLE IF EXISTS edgeTrafficBatchReceipts",
		"CREATE TABLE edgeTrafficBatchReceipts (role varchar(16) NOT NULL,nodeId bigint NOT NULL,batchId varchar(64) NOT NULL,payloadSHA char(64) NOT NULL,createdAt bigint NOT NULL,PRIMARY KEY(role,nodeId,batchId)) ENGINE=InnoDB",
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	defer db.Exec("DROP TABLE edgeAdmins")
	defer db.Exec("DROP TABLE edgeTrafficBatchReceipts")
	const legacyID = "0123456789abcdef0123456789abcdef"
	payload := []byte("legacy committed traffic")
	hash := sha256.Sum256(payload)
	if _, err := db.Exec("INSERT INTO edgeTrafficBatchReceipts VALUES ('node',1,?,?,UNIX_TIMESTAMP())", legacyID, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	// Separate sql.DB instances guarantee distinct simultaneous connections.
	var start sync.WaitGroup
	start.Add(1)
	var workers sync.WaitGroup
	errors := make(chan error, 6)
	for i := 0; i < cap(errors); i++ {
		other, err := dbs.NewInstanceFromConfig(&dbs.DBConfig{Driver: "mysql", Dsn: dsn})
		if err != nil {
			t.Fatal(err)
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer other.Close()
			start.Wait()
			errors <- EnsureSecuritySchema(other)
		}()
	}
	start.Done()
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal("simultaneous API startup migration failed:", err)
		}
	}
	if err := EnsureSecuritySchema(db); err != nil {
		t.Fatal("completed migration cannot be repeated:", err)
	}
	password := strings.Repeat("x", 100)
	if _, err := db.Exec("INSERT INTO edgeAdmins (id,password) VALUES (1,?)", password); err != nil {
		t.Fatal("same-version backport left the legacy password limit:", err)
	}
	called := 0
	update := func(*sql.Tx) error { called++; return nil }
	if err := statbatches.Apply(context.Background(), db.Raw(), "node", 1, legacyID, payload, update); err != nil || called != 0 {
		t.Fatalf("migration reapplied already committed traffic: calls=%d err=%v", called, err)
	}
	if err := statbatches.Apply(context.Background(), db.Raw(), "node", 1, strings.Repeat("a", 32), []byte("new traffic"), update); err != nil || called != 1 {
		t.Fatalf("migration default skipped new traffic: calls=%d err=%v", called, err)
	}
}

func TestSecuritySchemaCompletedMigrationNeedsNoDDLPrivileges(t *testing.T) {
	dsn := os.Getenv("EDGE_TEST_MYSQL_DSN")
	adminDSN := os.Getenv("EDGE_TEST_MYSQL_ADMIN_DSN")
	if dsn == "" || adminDSN == "" {
		t.Skip("set disposable EDGE_TEST_MYSQL_DSN and EDGE_TEST_MYSQL_ADMIN_DSN to test restricted privileges")
	}
	db, err := dbs.NewInstanceFromConfig(&dbs.DBConfig{Driver: "mysql", Dsn: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS edgeAdmins (id int PRIMARY KEY, password varchar(32), KEY password(password)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); err != nil {
		t.Fatal(err)
	}
	defer db.Exec("DROP TABLE edgeAdmins")
	defer db.Exec("DROP TABLE edgeTrafficBatchReceipts")
	if err := EnsureSecuritySchema(db); err != nil {
		t.Fatal(err)
	}
	config, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("mysql", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	user := "edge_schema_" + hex.EncodeToString(nonce[:8])
	password := hex.EncodeToString(nonce[:])
	account := "'" + user + "'@'%'"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := admin.ExecContext(ctx, "CREATE USER "+account+" IDENTIFIED BY '"+password+"'"); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP USER " + account)
		_ = admin.Close()
	})
	grant := fmt.Sprintf("GRANT SELECT,INSERT,UPDATE,DELETE ON `%s`.* TO %s", strings.ReplaceAll(config.DBName, "`", "``"), account)
	if _, err := admin.ExecContext(ctx, grant); err != nil {
		t.Fatal(err)
	}
	config.User, config.Passwd = user, password
	restricted, err := dbs.NewInstanceFromConfig(&dbs.DBConfig{Driver: "mysql", Dsn: config.FormatDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restricted.Close() })
	if err := EnsureSecuritySchema(restricted); err != nil {
		t.Fatal("already migrated API needs only metadata visibility and CRUD:", err)
	}
	if _, err := restricted.Exec("CREATE TABLE edgeSchemaForbiddenDDL (id int)"); err == nil {
		_, _ = admin.Exec("DROP TABLE edgeSchemaForbiddenDDL")
		t.Fatal("restricted fixture unexpectedly has DDL privileges")
	}
}
