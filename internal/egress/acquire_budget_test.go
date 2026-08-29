package egress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// acquireWith runs the real acquisition path against a loopback server, with
// only the address policy relaxed.
func acquireWith(t *testing.T, cfg Config, srcdest string, urls ...string) (*Acquisition, error) {
	t.Helper()
	previous := newAddressPolicy
	newAddressPolicy = func() (*AddressPolicy, error) { return &AddressPolicy{permitAll: true}, nil }
	t.Cleanup(func() { newAddressPolicy = previous })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return Acquire(ctx, frozen(t, urls...), srcdest, cfg)
}

// The transfer limit is a transaction budget. Applying it independently to
// each source would multiply the documented ceiling by the number of sources.
func TestTransferBudgetIsSharedAcrossAllDeclaredSources(t *testing.T) {
	const chunk = 4096
	body := strings.Repeat("A", chunk)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	cfg := testConfig()
	// Room for two sources and a byte, so the third must be what fails.
	cfg.MaxTransferBytes = 2*chunk + 1

	srcdest := t.TempDir()
	_, err := acquireWith(t, cfg, srcdest,
		server.URL+"/one.tar.gz", server.URL+"/two.tar.gz", server.URL+"/three.tar.gz")
	if err == nil {
		t.Fatal("three sources fitted inside a two-source budget")
	}
	if !strings.Contains(err.Error(), "acquisition budget") {
		t.Fatalf("failed for the wrong reason: %v", err)
	}
	// The two that fitted are legitimately on disk; the one that did not must
	// leave nothing behind for makepkg to find and checksum.
	if _, err := os.Stat(filepath.Join(srcdest, "three.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("a partial source survived a budget failure: %v", err)
	}
}

// A single source larger than the whole budget is the simple case, and it must
// leave no partial file: makepkg would otherwise find a truncated archive and
// fail its checksum for a reason nobody can trace back to here.
func TestAnOversizedSourceIsRefusedAndLeavesNothingBehind(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", 8192)))
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.MaxTransferBytes = 1024
	srcdest := t.TempDir()
	if _, err := acquireWith(t, cfg, srcdest, server.URL+"/big.tar.gz"); err == nil {
		t.Fatal("a source larger than the entire budget was accepted")
	}
	entries, err := os.ReadDir(srcdest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a refused source left files behind: %v", entries[0].Name())
	}
}

// A connection that is healthy at the TCP level and simply silent is not
// covered by any HTTP timeout. Without a stall guard it holds acquisition open
// for as long as the attacker cares to keep the socket alive.
func TestAStallingResponseBodyIsAbandoned(t *testing.T) {
	// The handler blocks, so the release must be closed before Close() waits on
	// it - defers run last-in-first-out, and the other order deadlocks the test.
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("start"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-release // and then nothing, ever
	}))
	defer server.Close()
	defer close(release)

	cfg := testConfig()
	cfg.IdleTimeoutSeconds = 1
	srcdest := t.TempDir()

	done := make(chan error, 1)
	go func() {
		_, err := acquireWith(t, cfg, srcdest, server.URL+"/slow.tar.gz")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a stalled transfer reported success")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a stalled transfer was never abandoned")
	}
	entries, _ := os.ReadDir(srcdest)
	if len(entries) != 0 {
		t.Fatalf("a stalled transfer left a partial file: %v", entries[0].Name())
	}
}

// A transfer that keeps making progress must not be killed by the idle guard,
// or every large source on a slow link becomes a failed build.
func TestASlowButProgressingTransferIsNotAbandoned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 6; i++ {
			_, _ = w.Write([]byte("chunk"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			time.Sleep(150 * time.Millisecond)
		}
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.IdleTimeoutSeconds = 1 // shorter than the total, longer than each gap
	srcdest := t.TempDir()
	result, err := acquireWith(t, cfg, srcdest, server.URL+"/slow.tar.gz")
	if err != nil {
		t.Fatalf("a progressing transfer was abandoned: %v", err)
	}
	if len(result.Fetched) != 1 || result.Fetched[0].Bytes != 30 {
		t.Fatalf("unexpected fetch record: %+v", result.Fetched)
	}
}

// The reserve is checked before each fetch, on the filesystem holding SRCDEST -
// which is under the user's state directory, outside the monitored worktree, so
// the build's workspace accounting never sees these bytes.
func TestAcquisitionRefusesToFillTheFilesystem(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	defer server.Close()

	cfg := testConfig()
	// A reserve larger than any real filesystem: nothing may be fetched.
	cfg.DiskReserveBytes = 1 << 62
	srcdest := t.TempDir()
	_, err := acquireWith(t, cfg, srcdest, server.URL+"/a.tar.gz")
	if err == nil || !strings.Contains(err.Error(), "reserve violated") {
		t.Fatalf("acquisition ignored the filesystem reserve: %v", err)
	}
	entries, _ := os.ReadDir(srcdest)
	if len(entries) != 0 {
		t.Fatalf("something was fetched despite the reserve: %v", entries[0].Name())
	}
}

// TestATransferStoppingAtTheReserveIsRefused covers the case the preflight
// could not: a fetch that begins with room to spare and would cross the reserve
// while it streams.
//
// checkReserve ran once, immediately before the request, and nothing then
// capped the copy. With the shipped defaults one source may transfer 8 GiB
// while the reserve is 2 GiB, so a filesystem with 6 GiB free passed the check
// and could still be driven to ENOSPC by an attacker-controlled response body.
// Removing the partial file afterwards returns the blocks; it does not return
// the writes other processes lost while the filesystem was full.
func TestATransferStoppingAtTheReserveIsRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", 65536)))
	}))
	defer server.Close()

	// A filesystem reporting 4 KiB of headroom above the reserve: the preflight
	// passes, and the body is far larger than what may still be written.
	const blockSize = 4096
	previous := acquisitionStatfs
	acquisitionStatfs = func(_ string, stat *unix.Statfs_t) error {
		stat.Bsize = blockSize
		stat.Blocks = 1024 // 4 MiB total, so the 10% floor is ~410 KiB
		stat.Bavail = 110  // ~440 KiB available: ~30 KiB above the floor
		return nil
	}
	defer func() { acquisitionStatfs = previous }()

	cfg := testConfig()
	// Small enough that the 10% floor is the effective reserve, so the preflight
	// passes with 4 KiB to spare and the body has to be stopped mid-stream.
	cfg.DiskReserveBytes = 1024
	srcdest := t.TempDir()
	_, err := acquireWith(t, cfg, srcdest, server.URL+"/big.tar.gz")
	if err == nil {
		t.Fatal("a transfer crossing the filesystem reserve was accepted")
	}
	if !strings.Contains(err.Error(), "reserve") {
		t.Fatalf("the failure does not name the reserve: %v", err)
	}
	entries, err := os.ReadDir(srcdest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a refused transfer left files behind: %v", entries[0].Name())
	}
}
