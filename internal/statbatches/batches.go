// Package statbatches atomically deduplicates a node's traffic uploads.
package statbatches

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
)

const MetadataKey = "x-edge-stat-batch"

// Apply records the receipt and all business updates in the same transaction.
// A retry with the same identity is accepted only for the exact same payload.
// An empty id is a legacy upload: it is atomic but cannot be deduplicated.
func Apply(ctx context.Context, db *sql.DB, role string, nodeID int64, id string, payload []byte, update func(*sql.Tx) error) error {
	if nodeID <= 0 || role == "" || len(role) > 16 || len(id) > 64 {
		return errors.New("invalid statistics batch identity")
	}
	if id != "" {
		if _, err := hex.DecodeString(id); err != nil || len(id) != 32 {
			return errors.New("invalid statistics batch ID")
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if id != "" {
		digest := sha256.Sum256(payload)
		hash := hex.EncodeToString(digest[:])
		_, err := tx.ExecContext(ctx, `INSERT INTO edgeTrafficBatchReceipts (role,nodeId,batchId,payloadSHA,createdAt) VALUES (?,?,?,?,UNIX_TIMESTAMP()) ON DUPLICATE KEY UPDATE batchId=batchId`, role, nodeID, id, hash)
		if err != nil {
			return err
		}
		var existing string
		var applied bool
		if err := tx.QueryRowContext(ctx, `SELECT payloadSHA,applied FROM edgeTrafficBatchReceipts WHERE role=? AND nodeId=? AND batchId=? FOR UPDATE`, role, nodeID, id).Scan(&existing, &applied); err != nil {
			return err
		}
		if hash != existing {
			return errors.New("statistics batch ID reused with different payload")
		}
		if applied {
			return tx.Commit()
		}
	}
	if err := update(tx); err != nil {
		return err
	}
	if id != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE edgeTrafficBatchReceipts SET applied=1 WHERE role=? AND nodeId=? AND batchId=?`, role, nodeID, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
