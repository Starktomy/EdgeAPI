package models

import (
	"errors"

	"github.com/TeaOSLab/EdgeAPI/internal/db/utils"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
	"github.com/iwind/TeaGo/dbs"
	"github.com/iwind/TeaGo/rands"
	"google.golang.org/protobuf/proto"
)

// PersistHTTPAccessLogs acknowledges a batch only after the selected log
// database commits it. Intentional sampling remains explicit; queue pressure
// no longer turns a successful RPC into silent data loss.
func (this *HTTPAccessLogDAO) PersistHTTPAccessLogs(logs []*pb.HTTPAccessLog) error {
	selected := randomHTTPAccessLogDAO()
	if selected == nil {
		selected = &HTTPAccessLogDAOWrapper{DAO: this}
	}
	if (selected.IsLocal || selected.DAO == this && dbutils.IsLocalDatabase) && !dbutils.HasFreeSpace {
		return errors.New("access log database has insufficient free space")
	}
	return selected.DAO.Instance.RunTx(func(tx *dbs.Tx) error {
		for _, log := range logs {
			if log == nil {
				return errors.New("nil access log")
			}
			if log.FirewallPolicyId == 0 && (accessLogQueuePercent <= 0 || accessLogQueuePercent < 100 && rands.Int(1, 100) > accessLogQueuePercent) {
				continue
			}
			// The existing row encoder extracts RequestBody. Keep the caller's
			// batch intact so retries after rollback still contain the body.
			copy := proto.Clone(log).(*pb.HTTPAccessLog)
			if err := this.CreateHTTPAccessLog(tx, selected.DAO, copy); err != nil {
				return err
			}
		}
		return nil
	})
}
