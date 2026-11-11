package models

import (
	"context"
	"errors"
	"strings"

	"github.com/iwind/TeaGo/dbs"
)

// UpdateNodeActiveContext bounds stream cleanup even when the database is
// unavailable. Direct context-aware execution also avoids TeaGo's reusable
// statement timestamp race.
func (this *NodeDAO) UpdateNodeActiveContext(ctx context.Context, nodeID int64, active bool) error {
	if nodeID <= 0 {
		return errors.New("invalid nodeId")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	db := this.Instance
	if db == nil {
		var err error
		db, err = dbs.Instance(this.DB)
		if err != nil {
			return err
		}
	}
	table := "`" + strings.ReplaceAll(this.Table, "`", "``") + "`"
	_, err := db.Raw().ExecContext(ctx, "UPDATE "+table+" SET isActive=?,inactiveNotifiedAt=0 WHERE id=?", active, nodeID)
	return err
}
