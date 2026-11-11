package models_test

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/iwind/TeaGo/dbs"
)

// This driver keeps one task in memory and exercises the DAO's actual generated
// statements without a database or network. Both reads and writes must carry
// the authenticated node and role; an unscoped write is rejected by the driver.
type taskSecurityDriver struct {
	updates                int
	password               string
	passwordUpdates        int
	replaceBeforeMigration bool
}
type taskSecurityConn struct{ store *taskSecurityDriver }
type taskSecurityStmt struct {
	store *taskSecurityDriver
	query string
}
type taskSecurityRows struct {
	columns []string
	values  []driver.Value
}

var taskSecurityDriverId atomic.Int64
var taskSecurityFields = regexp.MustCompile("[`\"]?([a-zA-Z0-9_]+)[`\"]?\\s*=\\s*\\?")

func (d *taskSecurityDriver) Open(string) (driver.Conn, error) {
	return &taskSecurityConn{store: d}, nil
}
func (c *taskSecurityConn) Prepare(query string) (driver.Stmt, error) {
	return &taskSecurityStmt{store: c.store, query: query}, nil
}
func (*taskSecurityConn) Close() error { return nil }
func (*taskSecurityConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not used by this test")
}
func (*taskSecurityStmt) Close() error  { return nil }
func (*taskSecurityStmt) NumInput() int { return -1 }
func (s *taskSecurityStmt) matches(args []driver.Value) bool {
	conditions := map[string]driver.Value{}
	for i, field := range taskSecurityFields.FindAllStringSubmatch(s.query, -1) {
		if i >= len(args) {
			return false
		}
		conditions[field[1]] = args[i]
	}
	return conditions["id"] == int64(1) && conditions["role"] == "node" && conditions["nodeId"] == int64(7)
}
func (s *taskSecurityStmt) Query(args []driver.Value) (driver.Rows, error) {
	if strings.Contains(s.query, "@@max_prepared_stmt_count") {
		return &taskSecurityRows{columns: []string{"max"}, values: []driver.Value{int64(100)}}, nil
	}
	if strings.Contains(s.query, "edgeAdmins") {
		return &taskSecurityRows{columns: []string{"id", "password"}, values: []driver.Value{int64(1), s.store.password}}, nil
	}
	rows := &taskSecurityRows{columns: []string{"id"}}
	if s.matches(args) {
		if strings.Contains(s.query, `"type"`) || strings.Contains(s.query, "`type`") {
			rows.columns, rows.values = []string{"type"}, []driver.Value{"serverChanged"}
		} else {
			rows.values = []driver.Value{int64(1)}
		}
	}
	return rows, nil
}
func (s *taskSecurityStmt) Exec(args []driver.Value) (driver.Result, error) {
	if strings.Contains(s.query, "edgeAdmins") {
		// Match the actual update's replacement and previous password values.
		if len(args) < 3 || s.store.replaceBeforeMigration {
			return driver.RowsAffected(0), nil
		}
		replacement, ok := args[0].(string)
		if !ok || !strings.HasPrefix(replacement, "$argon2id$") {
			return nil, errors.New("password migration did not persist Argon2id")
		}
		foundPrevious := false
		for _, arg := range args[1:] {
			if arg == s.store.password {
				foundPrevious = true
			}
		}
		if !foundPrevious {
			return nil, errors.New("password migration did not compare the previous hash")
		}
		s.store.password = replacement
		s.store.passwordUpdates++
		return driver.RowsAffected(1), nil
	}
	if !s.matches(args) {
		return nil, errors.New("task update is not scoped to its owner")
	}
	s.store.updates++
	return driver.RowsAffected(1), nil
}
func (r *taskSecurityRows) Columns() []string { return r.columns }
func (*taskSecurityRows) Close() error        { return nil }
func (r *taskSecurityRows) Next(dest []driver.Value) error {
	if r.values == nil {
		return io.EOF
	}
	copy(dest, r.values)
	r.values = nil
	return nil
}

func TestSecurityNodeTaskCompletionCannotChangeOtherNodes(t *testing.T) {
	store := &taskSecurityDriver{}
	name := "edgeapi-security-task-" + strconv.FormatInt(taskSecurityDriverId.Add(1), 10)
	sql.Register(name, store)
	db, err := dbs.NewInstanceFromConfig(&dbs.DBConfig{Driver: name})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dao := &models.NodeTaskDAO{DAOObject: dbs.DAOObject{Instance: db, Table: "edgeNodeTasks", PkName: "id", Model: new(models.NodeTask)}}
	for _, principal := range []struct {
		role   string
		nodeId int64
	}{{"node", 8}, {"dns", 7}} {
		if err := dao.UpdateNodeTaskDoneForNode(nil, principal.role, principal.nodeId, 1, true, ""); err == nil {
			t.Fatalf("%s/%d completed another node's task", principal.role, principal.nodeId)
		}
	}
	if store.updates != 0 {
		t.Fatal("unauthorized task completion mutated storage")
	}
	if err := dao.UpdateNodeTaskDoneForNode(nil, "node", 7, 1, true, ""); err != nil {
		t.Fatalf("owner could not complete task: %v", err)
	}
	if store.updates != 1 {
		t.Fatalf("authorized task updates = %d, want 1", store.updates)
	}
}
