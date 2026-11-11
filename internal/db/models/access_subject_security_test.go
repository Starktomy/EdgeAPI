package models_test

import (
	"testing"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
)

func TestSecurityAccessCredentialsRejectAmbiguousSubjects(t *testing.T) {
	for _, subject := range [][2]int64{{1, 42}, {0, 0}, {-1, 42}, {1, -1}} {
		// Invalid identities must fail before any database access. A nil DAO also
		// makes accidentally reaching storage a test failure.
		if _, err := (*models.UserAccessKeyDAO)(nil).CreateAccessKey(nil, subject[0], subject[1], "test"); err == nil {
			t.Fatalf("CreateAccessKey accepted ambiguous identity %v", subject)
		}
		if _, _, err := (*models.APIAccessTokenDAO)(nil).GenerateAccessToken(nil, subject[0], subject[1]); err == nil {
			t.Fatalf("GenerateAccessToken accepted ambiguous identity %v", subject)
		}
	}
}
