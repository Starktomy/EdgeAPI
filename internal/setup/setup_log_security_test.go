package setup

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSecuritySetupLogReplacesLinksWithoutTruncatingTargets(t *testing.T) {
	for _, test := range []struct {
		name string
		link func(string, string) error
	}{{"symlink", os.Symlink}, {"hardlink", os.Link}} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "marker")
			if err := os.WriteFile(marker, []byte("retained-original"), 0600); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(dir, "edge-install.log")
			if err := test.link(marker, logPath); err != nil {
				if runtime.GOOS == "windows" {
					t.Skip("link creation requires platform privileges")
				}
				t.Fatal(err)
			}
			file, err := openSetupLog(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString("new install progress"); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(marker); err != nil || string(data) != "retained-original" {
				t.Fatal("setup log truncated the linked target", err)
			}
			info, err := os.Lstat(logPath)
			if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Fatalf("setup log entry is not a private regular file: %v, %v", info, err)
			}
			if data, err := os.ReadFile(logPath); err != nil || string(data) != "new install progress" {
				t.Fatal("the fixed log filename no longer exposes current progress", err)
			}
		})
	}
}
