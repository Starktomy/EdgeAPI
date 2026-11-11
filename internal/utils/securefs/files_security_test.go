package securefs

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestSecurityCredentialWritesTightenModesAndRejectLinks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "configs")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api.yaml")
	if err := os.WriteFile(path, []byte("public-old-value"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("private-new-value")); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{dir: 0700, path: 0600} {
		info, err := os.Stat(name)
		if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != mode {
			t.Fatalf("credential path %s has unsafe mode or cannot be read: %v, %v", name, info, err)
		}
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		if runtime.GOOS == "windows" {
			return
		}
		t.Fatal(err)
	}
	if err := WriteFile(link, []byte("unexpected")); err == nil {
		t.Fatal("credential writer followed a symbolic link")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "private-new-value" {
		t.Fatal("symbolic-link destination changed", err)
	}
	parentLink := filepath.Join(t.TempDir(), "configs")
	if err := os.Symlink(dir, parentLink); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(filepath.Join(parentLink, "through-link.yaml"), []byte("unexpected")); err == nil {
		t.Fatal("credential directory symbolic link was accepted")
	}
}

func TestSecurityConcurrentCredentialReplacementNeverPublishesPartialData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "configs", "db.yaml")
	a := make([]byte, 8192)
	b := make([]byte, 8192)
	for i := range a {
		a[i], b[i] = 'a', 'b'
	}
	if err := WriteFile(path, a); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for _, value := range [][]byte{a, b} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 20; i++ {
				if err := WriteFile(path, value); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for i := 0; i < 40; i++ {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != string(a) && string(data) != string(b) {
			t.Fatalf("partial credential file published: bytes=%d err=%v", len(data), err)
		}
	}
	workers.Wait()
}
