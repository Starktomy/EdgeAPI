package models

import (
	"github.com/TeaOSLab/EdgeCommon/pkg/nodeconfigs"
	_ "github.com/go-sql-driver/mysql"
	"github.com/iwind/TeaGo/Tea"
	"github.com/iwind/TeaGo/dbs"
)

const (
	ApiTokenStateEnabled  = 1 // 已启用
	ApiTokenStateDisabled = 0 // 已禁用
)

type ApiTokenDAO dbs.DAO

func NewApiTokenDAO() *ApiTokenDAO {
	return dbs.NewDAO(&ApiTokenDAO{
		DAOObject: dbs.DAOObject{
			DB:     Tea.Env,
			Table:  "edgeAPITokens",
			Model:  new(ApiToken),
			PkName: "id",
		},
	}).(*ApiTokenDAO)
}

var SharedApiTokenDAO *ApiTokenDAO

func init() {
	dbs.OnReady(func() {
		SharedApiTokenDAO = NewApiTokenDAO()
	})
}

// EnableApiToken 启用条目
func (this *ApiTokenDAO) EnableApiToken(tx *dbs.Tx, id uint32) (rowsAffected int64, err error) {
	return this.Query(tx).
		Pk(id).
		Set("state", ApiTokenStateEnabled).
		Update()
}

// DisableApiToken 禁用条目
func (this *ApiTokenDAO) DisableApiToken(tx *dbs.Tx, id uint32) (rowsAffected int64, err error) {
	return this.Query(tx).
		Pk(id).
		Set("state", ApiTokenStateDisabled).
		Update()
}

// FindEnabledApiToken 查找启用中的条目
func (this *ApiTokenDAO) FindEnabledApiToken(tx *dbs.Tx, id uint32) (*ApiToken, error) {
	result, err := this.Query(tx).
		Pk(id).
		Attr("state", ApiTokenStateEnabled).
		Find()
	if result == nil {
		return nil, err
	}
	return result.(*ApiToken), err
}

// FindEnabledTokenWithNodeCacheable retains the old API, but credentials are
// read authoritatively so revocation and key rotation apply across API nodes.
func (this *ApiTokenDAO) FindEnabledTokenWithNodeCacheable(tx *dbs.Tx, nodeId string) (*ApiToken, error) {
	return this.FindEnabledTokenWithNode(tx, nodeId)
}

// FindEnabledTokenWithNode 获取节点Token信息并可以缓存
func (this *ApiTokenDAO) FindEnabledTokenWithNode(tx *dbs.Tx, nodeId string) (*ApiToken, error) {
	one, err := this.Query(tx).
		Attr("nodeId", nodeId).
		State(ApiTokenStateEnabled).
		Find()
	if one != nil {
		return one.(*ApiToken), nil
	}
	return nil, err
}

// FindEnabledTokenWithRole 根据角色获取节点
func (this *ApiTokenDAO) FindEnabledTokenWithRole(tx *dbs.Tx, role string) (*ApiToken, error) {
	one, err := this.Query(tx).
		Attr("role", role).
		State(ApiTokenStateEnabled).
		Find()
	if one != nil {
		return one.(*ApiToken), nil
	}
	return nil, err
}

// CreateAPIToken 保存API Token
func (this *ApiTokenDAO) CreateAPIToken(tx *dbs.Tx, nodeId string, secret string, role nodeconfigs.NodeRole) error {
	var op = NewApiTokenOperator()
	op.NodeId = nodeId
	op.Secret = secret
	op.Role = role
	op.State = ApiTokenStateEnabled
	err := this.Save(tx, op)
	return err
}

// FindAllEnabledAPITokens 读取API令牌
func (this *ApiTokenDAO) FindAllEnabledAPITokens(tx *dbs.Tx, role string) (result []*ApiToken, err error) {
	_, err = this.Query(tx).
		Attr("role", role).
		State(ApiTokenStateEnabled).
		Slice(&result).
		FindAll()
	return
}
