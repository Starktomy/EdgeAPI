package services

import (
	"context"
	"errors"
	"testing"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	rpcutils "github.com/TeaOSLab/EdgeAPI/internal/rpc/utils"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
)

var errOtherTenant = errors.New("resource belongs to another tenant")

type securityAuthorizer struct {
	headerUser    int64
	headerId      int64
	websocketUser int64
	websocketId   int64
	serverUser    int64
	serverId      int64
	webUser       int64
	webId         int64
	superAdmin    int64
}

func (a *securityAuthorizer) CheckUserHeader(userId int64, headerId int64) error {
	a.headerUser, a.headerId = userId, headerId
	return errOtherTenant
}

func (a *securityAuthorizer) CheckUserWebsocket(userId int64, websocketId int64) error {
	a.websocketUser, a.websocketId = userId, websocketId
	return errOtherTenant
}

func (a *securityAuthorizer) CheckUserWeb(userId int64, webId int64) error {
	a.webUser, a.webId = userId, webId
	return errOtherTenant
}

func (a *securityAuthorizer) CheckUserServer(userId int64, serverId int64) error {
	a.serverUser, a.serverId = userId, serverId
	return nil
}

func (a *securityAuthorizer) IsSuperAdmin(adminId int64) (bool, error) {
	return adminId == a.superAdmin, nil
}

func TestSecurityHeaderOwnershipAtRPCBoundary(t *testing.T) {
	ctx := rpcutils.NewPlainContext(rpcutils.UserTypeUser, 42)
	auth := &securityAuthorizer{}
	service := &HTTPHeaderService{BaseService: BaseService{authorization: auth}}
	if _, err := service.UpdateHTTPHeader(ctx, &pb.UpdateHTTPHeaderRequest{HeaderId: 9}); !errors.Is(err, errOtherTenant) {
		t.Fatalf("cross-tenant update was not rejected: %v", err)
	}
	if _, err := service.FindEnabledHTTPHeaderConfig(ctx, &pb.FindEnabledHTTPHeaderConfigRequest{HeaderId: 9}); !errors.Is(err, errOtherTenant) {
		t.Fatalf("cross-tenant read was not rejected: %v", err)
	}
	if auth.headerUser != 42 || auth.headerId != 9 {
		t.Fatalf("authorization used user=%d header=%d", auth.headerUser, auth.headerId)
	}
}

func TestSecurityWebsocketOwnershipAtRPCBoundary(t *testing.T) {
	auth := &securityAuthorizer{}
	service := &HTTPWebsocketService{BaseService: BaseService{authorization: auth}}
	if _, err := service.UpdateHTTPWebsocket(rpcutils.NewPlainContext(rpcutils.UserTypeUser, 42), &pb.UpdateHTTPWebsocketRequest{WebsocketId: 9, AllowAllOrigins: true}); !errors.Is(err, errOtherTenant) {
		t.Fatalf("cross-tenant websocket update was not rejected: %v", err)
	}
	if auth.websocketUser != 42 || auth.websocketId != 9 {
		t.Fatal("did not authorize the requested websocket for the authenticated user")
	}
}

func TestSecurityServerWebReferenceRequiresTargetPermission(t *testing.T) {
	auth := &securityAuthorizer{}
	service := &ServerService{BaseService: BaseService{authorization: auth}}
	_, err := service.UpdateServerWeb(rpcutils.NewPlainContext(rpcutils.UserTypeUser, 42), &pb.UpdateServerWebRequest{ServerId: 1, WebId: 9})
	if !errors.Is(err, errOtherTenant) || auth.serverUser != 42 || auth.serverId != 1 || auth.webUser != 42 || auth.webId != 9 {
		t.Fatalf("own server permitted referencing unauthorized web: %v, authorization=%+v", err, auth)
	}
}

func TestSecurityUserCannotCreateLocalRoot(t *testing.T) {
	_, err := (&HTTPWebService{}).CreateHTTPWeb(rpcutils.NewPlainContext(rpcutils.UserTypeUser, 42), &pb.CreateHTTPWebRequest{RootJSON: []byte(`{"isOn":true,"dir":"/"}`)})
	if err == nil {
		t.Fatal("user-created local filesystem root must be rejected before storage")
	}
}

func TestSecurityHistoricalMixedAccessKeysCannotBeExchanged(t *testing.T) {
	service := &APIAccessTokenService{findAccessKey: func(string) (*models.UserAccessKey, error) {
		return &models.UserAccessKey{AdminId: 1, UserId: 42, Secret: "secret"}, nil
	}}
	for _, role := range []string{"admin", "user"} {
		if _, err := service.GetAPIAccessToken(context.Background(), &pb.GetAPIAccessTokenRequest{Type: role, AccessKeyId: "key", AccessKey: "secret"}); err == nil {
			t.Fatalf("historical mixed key exchanged as %s", role)
		}
	}
}

func TestSecurityAdministratorManagementRequiresSuperAdmin(t *testing.T) {
	auth := &securityAuthorizer{superAdmin: 1}
	service := &AdminService{BaseService: BaseService{authorization: auth}}
	ctx := rpcutils.NewPlainContext(rpcutils.UserTypeAdmin, 2)
	for _, operation := range []func() error{
		func() error { _, err := service.CreateAdmin(ctx, &pb.CreateAdminRequest{IsSuper: true}); return err },
		func() error {
			_, err := service.UpdateAdmin(ctx, &pb.UpdateAdminRequest{AdminId: 2, IsSuper: true})
			return err
		},
		func() error { _, err := service.DeleteAdmin(ctx, &pb.DeleteAdminRequest{AdminId: 1}); return err },
		func() error {
			_, err := service.CreateOrUpdateAdmin(ctx, &pb.CreateOrUpdateAdminRequest{Username: "new-admin"})
			return err
		},
		func() error {
			_, err := service.UpdateAdminLogin(ctx, &pb.UpdateAdminLoginRequest{AdminId: 1})
			return err
		},
	} {
		if err := operation(); err == nil {
			t.Fatal("restricted administrator performed an administrator management operation")
		}
	}
	if _, err := service.ValidateSuperAdmin(rpcutils.NewPlainContext(rpcutils.UserTypeAdmin, 1)); err != nil {
		t.Fatalf("super administrator rejected: %v", err)
	}
	if err := service.validateAdminAccountMutation(ctx, 2, true); err != nil {
		t.Fatalf("self profile/password update rejected: %v", err)
	}
	if err := service.validateAdminAccountMutation(rpcutils.NewMockAdminNodeContext(0), 1, true); err != nil {
		t.Fatalf("signed setup service identity rejected: %v", err)
	}
}

func TestSecurityInfrastructureCredentialsRejectUserPrincipals(t *testing.T) {
	ctx := rpcutils.NewPlainContext(rpcutils.UserTypeUser, 42)
	if _, err := (&NodeService{}).FindAllEnabledNodesWithNodeClusterId(ctx, &pb.FindAllEnabledNodesWithNodeClusterIdRequest{NodeClusterId: 1}); err == nil {
		t.Fatal("user principal accessed node credentials")
	}
	if _, err := (&NodeClusterService{}).FindEnabledNodeCluster(ctx, &pb.FindEnabledNodeClusterRequest{NodeClusterId: 1}); err == nil {
		t.Fatal("user principal accessed cluster credentials")
	}
}

func TestSecurityEdgeNodeCannotUseAdministratorLogin(t *testing.T) {
	if _, err := (&AdminService{}).LoginAdmin(rpcutils.NewMockNodeContext(7), &pb.LoginAdminRequest{Username: "admin", Password: "raw-v1:password"}); err == nil {
		t.Fatal("edge node credential reached administrator password verification")
	}
}
