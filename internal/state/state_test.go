package state

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewDirsEnvOverrides(t *testing.T) {
	t.Setenv("OM_HOME", "/h")
	t.Setenv("OM_CONFIG_DIR", "/c")
	t.Setenv("OM_STATE_DIR", "/s")
	d := NewDirs()
	if d.Home != "/h" || d.UserEnv != filepath.Join("/c", "om.env") || d.Registry != filepath.Join("/s", "registry", "workspaces.json") {
		t.Fatalf("bad dirs: %+v", d)
	}
	if d.CoreRoutes != filepath.Join("/h", "core", "caddy", "conf.d") {
		t.Fatal(d.CoreRoutes)
	}
}

func TestXDGDefaults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	t.Setenv("OM_CONFIG_DIR", "")
	t.Setenv("OM_STATE_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "/x/c")
	t.Setenv("XDG_STATE_HOME", "/x/s")
	d := NewDirs()
	if d.Config != "/x/c/om" || d.State != "/x/s/om" {
		t.Fatalf("%+v", d)
	}
}

func TestParseEnvFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "om.env")
	os.WriteFile(p, []byte("# c\n\nA=1\n B = \"x y\" \nC='q'\nnoeq\nD=a=b\nE=\n"), 0o644)
	got, err := ParseEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"A": "1", "B": "x y", "C": "q", "D": "a=b", "E": ""}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s=%q want %q", k, got[k], v)
		}
	}
	if m, err := ParseEnvFile(p + ".missing"); err != nil || len(m) != 0 {
		t.Fatal("missing file must be empty, no error")
	}
}

func TestIsNumber(t *testing.T) {
	for s, want := range map[string]bool{"80": true, "": false, "²": false, "８０": false, "8a": false, "-1": false} {
		if IsNumber(s) != want {
			t.Errorf("%q", s)
		}
	}
}

func TestWritePrivateMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a", "secret")
	if err := WritePrivate(p, "x"); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Fatal("tmp left behind")
	}
}

func TestRunMissingBinary(t *testing.T) {
	r := Run([]string{"/nonexistent/om-test-bin"})
	if r.Code != 127 || r.Stderr == "" {
		t.Fatalf("%+v", r)
	}
	if r := Run([]string{"sh", "-c", "echo hi; exit 3"}); runtime.GOOS != "windows" && (r.Code != 3 || r.Stdout != "hi\n") {
		t.Fatalf("%+v", r)
	}
}

func TestFileLockExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "l")
	var wg sync.WaitGroup
	var inside, n atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			un, err := FileLock(p)
			if err != nil {
				t.Error(err)
				return
			}
			if inside.Add(1) != 1 {
				t.Error("two holders at once")
			}
			time.Sleep(time.Millisecond)
			inside.Add(-1)
			n.Add(1)
			un()
		}()
	}
	wg.Wait()
	if n.Load() != 8 {
		t.Fatal(n.Load())
	}
}
