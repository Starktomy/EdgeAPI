// Package securefs persists credentials with private modes and atomic replacement.
package securefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

func PrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("credential directory must be a directory, not a symbolic link")
	}
	return os.Chmod(path, 0700)
}

// WriteFile replaces the target without following its symbolic link. Holding
// an os.Root also pins the directory while creating and renaming the temporary
// file. A new 0600 inode tightens the permissions of previously public files.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := PrivateDir(dir); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err == nil && !info.Mode().IsRegular() {
		return errors.New("credential target must be a regular file")
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := ".edge-secret-" + hex.EncodeToString(random[:])
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temporary)
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
