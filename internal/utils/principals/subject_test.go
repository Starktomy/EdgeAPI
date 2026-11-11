package principals

import "testing"

func TestValidateRoleSubject(t *testing.T) {
	for _, test := range []struct {
		name    string
		role    string
		adminId int64
		userId  int64
		allowed bool
	}{
		{"admin key", "admin", 1, 0, true},
		{"user key", "user", 0, 42, true},
		{"mixed key requested as user", "user", 1, 42, false},
		{"mixed key requested as admin", "admin", 1, 42, false},
		{"user key requested as admin", "admin", 0, 42, false},
		{"admin key requested as user", "user", 1, 0, false},
		{"empty identity", "user", 0, 0, false},
		{"negative admin identity", "user", -1, 42, false},
		{"negative user identity", "admin", 1, -1, false},
		{"machine type", "api", 1, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateRoleSubject(test.role, test.adminId, test.userId); (err == nil) != test.allowed {
				t.Fatalf("ValidateRoleSubject(%q, %d, %d) = %v, allowed %v", test.role, test.adminId, test.userId, err, test.allowed)
			}
		})
	}
}
