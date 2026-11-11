package models_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/iwind/TeaGo/dbs"
)

type streamStatusDriver struct{ block bool }
type streamStatusConn struct{ store *streamStatusDriver }
type streamStatusStmt struct{}
type streamStatusRows struct{ read bool }

var streamStatusDriverID atomic.Int64

func (d *streamStatusDriver) Open(string) (driver.Conn, error) {
	return &streamStatusConn{store: d}, nil
}
func (*streamStatusConn) Close() error { return nil }
func (*streamStatusConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected status transaction")
}
func (*streamStatusConn) Prepare(query string) (driver.Stmt, error) {
	if !strings.Contains(query, "@@max_prepared_stmt_count") {
		return nil, errors.New("stream status cleanup must use context-aware direct execution")
	}
	return &streamStatusStmt{}, nil
}
func (c *streamStatusConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if query != "UPDATE `edgeNodes` SET isActive=?,inactiveNotifiedAt=0 WHERE id=?" || len(args) != 2 || args[0].Value != false || args[1].Value != int64(7) {
		return nil, errors.New("stream cleanup omitted its authenticated node or offline status")
	}
	if c.store.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return driver.RowsAffected(1), nil
}
func (*streamStatusStmt) Close() error  { return nil }
func (*streamStatusStmt) NumInput() int { return -1 }
func (*streamStatusStmt) Query([]driver.Value) (driver.Rows, error) {
	return &streamStatusRows{}, nil
}
func (*streamStatusStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("unexpected prepared status update")
}
func (*streamStatusRows) Columns() []string { return []string{"max"} }
func (*streamStatusRows) Close() error      { return nil }
func (r *streamStatusRows) Next(dest []driver.Value) error {
	if r.read {
		return io.EOF
	}
	r.read, dest[0] = true, int64(100)
	return nil
}

func TestSecurityNodeStreamOfflineCleanupHonorsDeadline(t *testing.T) {
	store := &streamStatusDriver{}
	driverName := "edgeapi-stream-status-" + strconv.FormatInt(streamStatusDriverID.Add(1), 10)
	sql.Register(driverName, store)
	db, err := dbs.NewInstanceFromConfig(&dbs.DBConfig{Driver: driverName})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dao := &models.NodeDAO{DAOObject: dbs.DAOObject{Instance: db, Table: "edgeNodes", Model: new(models.Node), PkName: "id"}}
	if err := dao.UpdateNodeActiveContext(context.Background(), 7, false); err != nil {
		t.Fatalf("normal stream status cleanup failed: %v", err)
	}
	store.block = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := dao.UpdateNodeActiveContext(ctx, 7, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked status cleanup did not honor its deadline: %v", err)
	}
}
