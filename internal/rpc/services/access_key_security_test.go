package services_test

import (
	"testing"

	"github.com/TeaOSLab/EdgeAPI/internal/rpc/services"
	rpcutils "github.com/TeaOSLab/EdgeAPI/internal/rpc/utils"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
)

func TestSecurityUserCannotCreateAdministratorAccessKey(t *testing.T) {
	service := &services.UserAccessKeyService{}
	_, err := service.CreateUserAccessKey(rpcutils.NewPlainContext(rpcutils.UserTypeUser, 42), &pb.CreateUserAccessKeyRequest{AdminId: 1})
	if err == nil {
		t.Fatal("tenant user was allowed to request an administrator key")
	}
}
