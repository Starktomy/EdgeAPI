package setup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/iwind/TeaGo/dbs"
)

// EnsureSecuritySchema also runs for an installation whose product version is
// unchanged. Security backports must not depend on a version-only upgrade gate.
func EnsureSecuritySchema(db *dbs.DB) (resultErr error) {
	var schema SQLDumpResult
	if err := json.Unmarshal(sqlData, &schema); err != nil {
		return err
	}
	receipts := schema.FindTable("edgeTrafficBatchReceipts")
	admins := schema.FindTable("edgeAdmins")
	if receipts == nil || admins == nil || admins.FindField("password") == nil || !strings.HasPrefix(receipts.Definition, "CREATE TABLE ") {
		return errors.New("security schema definitions missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, err := db.Raw().Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var database string
	if err := conn.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&database); err != nil || database == "" {
		return errors.Join(errors.New("security schema migration requires a selected database"), err)
	}
	// GET_LOCK is connection-scoped and survives DDL's implicit commits. Keep
	// the checks, ALTERs and RELEASE_LOCK on this dedicated connection; a pool
	// connection per statement would leave simultaneous API startups racing.
	digest := sha256.Sum256([]byte(database))
	lockName := fmt.Sprintf("edge:security-schema:%x", digest[:20])
	var locked sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 30)", lockName).Scan(&locked); err != nil {
		return err
	}
	if !locked.Valid || locked.Int64 != 1 {
		return errors.New("could not acquire security schema migration lock")
	}
	defer func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer releaseCancel()
		var released sql.NullInt64
		err := conn.QueryRowContext(releaseCtx, "SELECT RELEASE_LOCK(?)", lockName).Scan(&released)
		if err != nil || !released.Valid || released.Int64 != 1 {
			// Do not put a connection retaining an advisory lock back in the pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			resultErr = errors.Join(resultErr, errors.New("could not release security schema migration lock"), err)
		}
	}()

	var exists int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='edgeTrafficBatchReceipts'").Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		// Once migrated, normal startup only needs metadata visibility and CRUD
		// privileges. Do not demand CREATE TABLE on every restart.
		if _, err := conn.ExecContext(ctx, receipts.Definition); err != nil {
			return err
		}
	}
	var appliedDefault sql.NullString
	err = conn.QueryRowContext(ctx, "SELECT COLUMN_DEFAULT FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='edgeTrafficBatchReceipts' AND COLUMN_NAME='applied'").Scan(&appliedDefault)
	if errors.Is(err, sql.ErrNoRows) {
		// Receipts written by the earlier atomic protocol represent committed
		// business updates. Mark those rows applied instead of billing them again.
		// The default is reset separately so a crash between these DDL statements
		// is repaired on the next startup before new uploads are accepted.
		if _, err := conn.ExecContext(ctx, "ALTER TABLE edgeTrafficBatchReceipts ADD applied tinyint(1) NOT NULL DEFAULT 1"); err != nil {
			return err
		}
		appliedDefault = sql.NullString{String: "1", Valid: true}
	} else if err != nil {
		return err
	}
	if !appliedDefault.Valid || appliedDefault.String != "0" {
		if _, err := conn.ExecContext(ctx, "ALTER TABLE edgeTrafficBatchReceipts ALTER COLUMN applied SET DEFAULT 0"); err != nil {
			return err
		}
	}
	var passwordLength sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='edgeAdmins' AND COLUMN_NAME='password'").Scan(&passwordLength); err != nil {
		return fmt.Errorf("read administrator password column: %w", err)
	}
	if !passwordLength.Valid {
		return errors.New("administrator password column cannot store password hashes")
	}
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.statistics WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='edgeAdmins' AND INDEX_NAME='password'").Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		if _, err := conn.ExecContext(ctx, "ALTER TABLE edgeAdmins DROP INDEX password"); err != nil {
			return err
		}
	}
	if passwordLength.Int64 < 255 {
		if _, err := conn.ExecContext(ctx, "ALTER TABLE edgeAdmins MODIFY password "+admins.FindField("password").Definition); err != nil {
			return err
		}
	}
	return nil
}
