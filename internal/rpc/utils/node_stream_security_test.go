//go:build !plus

package rpcutils

import (
	"errors"
	"testing"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSecurityNodeStreamRevalidatesAuthoritativeIdentity(t *testing.T) {
	const secret = "stream-security-secret-at-least-32-bytes"
	ctx := signedRequestContext(t, "node-stream", secret, UserTypeNode, 999)
	for _, change := range []string{"removed credential", "rotated secret", "changed role", "disabled node", "replaced node", "credential database failure", "node database failure"} {
		t.Run(change, func(t *testing.T) {
			credential := &models.ApiToken{Secret: secret, Role: UserTypeNode}
			nodeID := int64(7)
			var credentialErr, nodeErr error
			id, validate, err := newNodeStreamValidator(ctx, func(machineID string) (*models.ApiToken, error) {
				if machineID != "node-stream" {
					t.Fatal("credential lookup changed machine identity")
				}
				return credential, credentialErr
			}, func(role UserType, machineID string) (int64, error) {
				if role != UserTypeNode || machineID != "node-stream" {
					t.Fatal("node lookup changed authenticated role or identity")
				}
				return nodeID, nodeErr
			})
			if err != nil || id != 7 {
				t.Fatalf("initial stream authentication: id=%d err=%v", id, err)
			}
			if err := validate(); err != nil {
				t.Fatalf("healthy session failed authoritative revalidation: %v", err)
			}
			want := codes.Unauthenticated
			switch change {
			case "removed credential":
				credential = nil
			case "rotated secret":
				credential.Secret = "replacement-secret-at-least-32-bytes"
			case "changed role":
				credential.Role = UserTypeAdmin
			case "disabled node":
				nodeID = 0
			case "replaced node":
				nodeID = 8
			case "credential database failure":
				credentialErr, want = errors.New("database unavailable"), codes.Unavailable
			case "node database failure":
				nodeErr, want = errors.New("database unavailable"), codes.Unavailable
			}
			if err := validate(); status.Code(err) != want {
				t.Fatalf("changed stream credential accepted or wrong status: %v", err)
			}
		})
	}
}
