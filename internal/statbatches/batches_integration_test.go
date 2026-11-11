package statbatches

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

// This uses only an explicitly supplied disposable test database.
func TestBatchRetryIsAtomicAndIdempotent(t *testing.T) {
	dsn := os.Getenv("EDGE_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set EDGE_TEST_MYSQL_DSN to a disposable MySQL database")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, query := range []string{
		`DROP TABLE IF EXISTS edgeTrafficBatchReceipts`,
		`CREATE TABLE edgeTrafficBatchReceipts (role varchar(16) NOT NULL,nodeId bigint NOT NULL,batchId varchar(64) NOT NULL,payloadSHA char(64) NOT NULL,createdAt bigint NOT NULL,applied bool NOT NULL DEFAULT 0,PRIMARY KEY(role,nodeId,batchId)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS batchTestTotals (id int PRIMARY KEY, total bigint NOT NULL) ENGINE=InnoDB`,
		`DELETE FROM edgeTrafficBatchReceipts`,
		`DELETE FROM batchTestTotals`,
		`INSERT INTO batchTestTotals VALUES(1,0)`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	const batchID = "0123456789abcdef0123456789abcdef"
	update := func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE batchTestTotals SET total=total+42 WHERE id=1`)
		return err
	}
	if err := Apply(ctx, db, "node", 1, batchID, []byte("first"), func(tx *sql.Tx) error {
		if err := update(tx); err != nil {
			return err
		}
		return errors.New("injected failure after a partial business update")
	}); err == nil {
		t.Fatal("failure was not returned")
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Apply(ctx, db, "node", 1, batchID, []byte("first"), update); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var total int64
	if err := db.QueryRow(`SELECT total FROM batchTestTotals WHERE id=1`).Scan(&total); err != nil || total != 42 {
		t.Fatalf("retried total=%d err=%v, want 42", total, err)
	}
	if err := Apply(ctx, db, "node", 1, batchID, []byte("changed"), update); err == nil {
		t.Fatal("same ID with a changed payload was accepted")
	}
	if err := Apply(ctx, db, "node", 2, batchID, []byte("first"), update); err != nil {
		t.Fatal("different node must have its own namespace:", err)
	}
	if err := db.QueryRow(`SELECT total FROM batchTestTotals WHERE id=1`).Scan(&total); err != nil || total != 84 {
		t.Fatalf("per-node total=%d err=%v, want 84", total, err)
	}
}
