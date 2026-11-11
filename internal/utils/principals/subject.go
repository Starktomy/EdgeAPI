package principals

import "errors"

// ValidateSubject requires exactly one account identity. Machine credentials and
// account access keys must not acquire a different identity by ID precedence.
func ValidateSubject(adminId int64, userId int64) error {
	if adminId < 0 || userId < 0 || (adminId > 0) == (userId > 0) {
		return errors.New("exactly one positive adminId or userId is required")
	}
	return nil
}

// ValidateRoleSubject also prevents exchanging a key for another account type.
func ValidateRoleSubject(role string, adminId int64, userId int64) error {
	if err := ValidateSubject(adminId, userId); err != nil {
		return err
	}
	if (role == "admin" && adminId > 0) || (role == "user" && userId > 0) {
		return nil
	}
	return errors.New("access key does not belong to the requested account type")
}
