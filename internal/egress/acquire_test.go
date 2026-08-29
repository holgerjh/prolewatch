package egress

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.ConnectTimeoutSeconds = 5
	// The production reserve is 2 GiB of free space on the source filesystem.
	// These tests are about transfer budgets, redirects, and what gets stored -
	// not about the host's free space - and inheriting the production value made
	// the whole package fail on any machine with less than 2 GiB free on TMPDIR.
	// A tmpfs /tmp on a 4 GiB VM is exactly that, and the failure names the
	// reserve rather than the test, so it reads as a product defect. The two
	// budget tests that do exercise the reserve set their own value.
	cfg.DiskReserveBytes = 4096
	return cfg
}

// The fetcher's address policy must be bypassable in tests only by supplying a
// permissive policy, never by the code under test deciding a loopback address
// is fine. This helper builds the client the same way Acquire does, with the
// policy swapped, so what is exercised is the real path.
func fetchThroughTestServer(t *testing.T, allowance *Allowance, srcdest string) (*Acquisition, error) {
	return fetchThroughTestServerWithProgress(t, allowance, srcdest, nil)
}

func fetchThroughTestServerWithProgress(t *testing.T, allowance *Allowance, srcdest string, progress ProgressFunc) (*Acquisition, error) {
	t.Helper()
	previous := newAddressPolicy
	newAddressPolicy = func() (*AddressPolicy, error) { return &AddressPolicy{permitAll: true}, nil }
	t.Cleanup(func() { newAddressPolicy = previous })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return AcquireWithProgress(ctx, allowance, srcdest, testConfig(), progress)
}

func TestAcquireFetchesDeclaredSourcesIntoSrcdest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dist/demo-1.0.tar.gz" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("payload bytes"))
	}))
	defer server.Close()

	srcdest := t.TempDir()
	allowance := frozen(t, server.URL+"/dist/demo-1.0.tar.gz")
	result, err := fetchThroughTestServer(t, allowance, srcdest)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(srcdest, "demo-1.0.tar.gz"))
	if err != nil || string(raw) != "payload bytes" {
		t.Fatalf("source not written under its makepkg name: %v %q", err, raw)
	}
	if len(result.Fetched) != 1 || result.Fetched[0].Bytes != 13 {
		t.Fatalf("unexpected fetch record: %+v", result.Fetched)
	}
	if len(result.Declared) != 1 || result.Declared[0].Raw != server.URL+"/dist/demo-1.0.tar.gz" {
		t.Fatalf("acquisition lost its frozen source explanation: %+v", result.Declared)
	}
}

func TestAcquireReportsMeasuredBytesAndKnownTotal(t *testing.T) {
	payload := []byte("payload bytes")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "13")
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	var updates []AcquisitionProgress
	_, err := fetchThroughTestServerWithProgress(t, frozen(t, server.URL+"/demo.tar.gz"), t.TempDir(), func(progress AcquisitionProgress) {
		updates = append(updates, progress)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) < 2 {
		t.Fatalf("transfer emitted no start/final progress: %+v", updates)
	}
	first, last := updates[0], updates[len(updates)-1]
	if first.Filename != "demo.tar.gz" || first.SourceIndex != 1 || first.SourceCount != 1 || first.Bytes != 0 || first.Total != int64(len(payload)) {
		t.Fatalf("invalid initial transfer progress: %+v", first)
	}
	if !last.Complete || last.Bytes != int64(len(payload)) || last.Total != int64(len(payload)) || last.BytesPerSecond <= 0 {
		t.Fatalf("invalid final transfer progress: %+v", last)
	}
}

// The bytes on disk must be the bytes on the wire.
//
// net/http adds Accept-Encoding: gzip on its own and transparently decodes the
// reply, which makes the saved file differ from what makepkg's own DLAGENT -
// curl, without --compressed - would have written. The PKGBUILD's checksum was
// computed over the latter, so a server that serves Content-Encoding: gzip
// would fail an otherwise valid package here and nowhere else.
func TestAcquireStoresTheEncodedBytesMakepkgWouldHaveStored(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("payload bytes")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var offered string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offered = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(compressed.Bytes())
	}))
	defer server.Close()

	srcdest := t.TempDir()
	allowance := frozen(t, server.URL+"/dist/demo-1.0.tar.gz")
	if _, err := fetchThroughTestServer(t, allowance, srcdest); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if strings.Contains(offered, "gzip") {
		t.Fatalf("the fetcher negotiated an encoding makepkg would not have: %q", offered)
	}
	raw, err := os.ReadFile(filepath.Join(srcdest, "demo-1.0.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, compressed.Bytes()) {
		t.Fatalf("the stored source was decoded in transit: %d bytes on disk, %d on the wire", len(raw), compressed.Len())
	}
}

// The name makepkg expects. Getting it wrong means makepkg re-downloads, which
// with zero network fails the build for a confusing reason.
func TestSourceFilenameMatchesWhatMakepkgLooksFor(t *testing.T) {
	for entry, want := range map[string]string{
		"https://example.com/dist/demo-1.0.tar.gz":       "demo-1.0.tar.gz",
		"demo.tar.gz::https://example.com/download?id=7": "demo.tar.gz",
		"https://example.com/a/b/c/file.patch":           "file.patch",
	} {
		for _, source := range mustParseSources(t, "\tsource = "+entry) {
			got, err := SourceFilename(source)
			if err != nil || got != want {
				t.Fatalf("%s -> %q (%v), want %q", entry, got, err, want)
			}
		}
	}
}

// The filename is attacker-authored and becomes a path.
func TestSourceFilenameRejectsTraversal(t *testing.T) {
	for _, entry := range []string{
		"../../../../etc/cron.d/evil::https://example.com/x",
		"/etc/passwd::https://example.com/x",
		"..::https://example.com/x",
		"https://example.com/",
	} {
		for _, source := range mustParseSources(t, "\tsource = "+entry) {
			if name, err := SourceFilename(source); err == nil {
				t.Fatalf("%s produced filename %q instead of an error", entry, name)
			}
		}
	}
}

// Redirects are followed transitively, and every host on the chain is recorded
// for the transaction report.
func TestAcquireFollowsRedirectsAndRecordsEveryHost(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("cdn payload"))
	}))
	defer final.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/cdn/demo-1.0.tar.gz", http.StatusFound)
	}))
	defer origin.Close()

	srcdest := t.TempDir()
	result, err := fetchThroughTestServer(t, frozen(t, origin.URL+"/demo-1.0.tar.gz"), srcdest)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if raw, _ := os.ReadFile(filepath.Join(srcdest, "demo-1.0.tar.gz")); string(raw) != "cdn payload" {
		t.Fatalf("redirected fetch did not land: %q", raw)
	}
	if len(result.Hosts()) == 0 {
		t.Fatal("no hosts recorded for the transaction report")
	}
}

func TestAcquireRefusesAnUnboundedRedirectLoop(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server.URL+"/again", http.StatusFound)
	}))
	defer server.Close()
	if _, err := fetchThroughTestServer(t, frozen(t, server.URL+"/demo-1.0.tar.gz"), t.TempDir()); err == nil {
		t.Fatal("an endless redirect chain was followed")
	}
}

// VCS sources are not fetched here: a checkout is a protocol conversation, not
// a fetch. They are reported as hosts makepkg itself must still reach.
func TestAcquireLeavesVCSSourcesToMakepkg(t *testing.T) {
	allowance := frozen(t, "git+https://gitlab.com/example/other.git#tag=v1", "fix.patch")
	result, err := fetchThroughTestServer(t, allowance, t.TempDir())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if len(result.Fetched) != 0 {
		t.Fatalf("a VCS or local source was fetched over HTTP: %+v", result.Fetched)
	}
	if strings.Join(result.VCSHosts, ",") != "gitlab.com" {
		t.Fatalf("VCS hosts = %v, want [gitlab.com]", result.VCSHosts)
	}
}

// A package with no VCS sources needs no network while its own shell runs.
func TestPackagesWithoutVCSSourcesNeedNoNetworkDuringRetrieval(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
	}))
	defer server.Close()
	result, err := fetchThroughTestServer(t, frozen(t, server.URL+"/demo.tar.gz", "local.patch"), t.TempDir())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if len(result.VCSHosts) != 0 {
		t.Fatalf("expected no network requirement, got %v", result.VCSHosts)
	}
}

func TestAcquireRefusesNonPublicDestinations(t *testing.T) {
	// The real policy, not the permissive test one: a loopback httptest server
	// is exactly the non-public destination the policy exists to refuse.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should never arrive"))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := Acquire(ctx, frozen(t, server.URL+"/demo.tar.gz"), t.TempDir(), testConfig()); err == nil {
		t.Fatal("a loopback destination was fetched")
	}
}

func TestAcquireRefusesUnsupportedSchemes(t *testing.T) {
	if _, err := fetchThroughTestServer(t, frozen(t, "ftp://example.com/demo.tar.gz"), t.TempDir()); err == nil {
		t.Fatal("an ftp source was accepted")
	}
}

func TestAcquireRequiresAFrozenAllowance(t *testing.T) {
	if _, err := Acquire(context.Background(), nil, t.TempDir(), testConfig()); err == nil {
		t.Fatal("acquisition without a frozen allowance must be refused")
	}
}

// The local-interface capture is the only part of the policy that can recognise
// a service on this host's own globally routable address, or on a directly
// attached public subnet. The generic reserved-range checks cannot: those
// addresses are public by every definition except the one that matters here.
//
// So an enumeration failure must stop the fetch. Ignoring it leaves a policy
// that still passes every reserved-range test and is quietly missing exactly
// the addresses it was built to find.
func TestEnumerationFailureStopsAcquisitionRatherThanWeakeningIt(t *testing.T) {
	previousInterfaces, previousAddrs := networkInterfaces, networkInterfaceAddrs
	defer func() { networkInterfaces, networkInterfaceAddrs = previousInterfaces, previousAddrs }()

	networkInterfaces = func() ([]net.Interface, error) { return nil, errors.New("enumeration unavailable") }
	if _, err := NewAddressPolicy(); err == nil {
		t.Fatal("a policy with no local addresses was reported as complete")
	}

	networkInterfaces = func() ([]net.Interface, error) { return []net.Interface{{Index: 1, Name: "eth0"}}, nil }
	networkInterfaceAddrs = func(*net.Interface) ([]net.Addr, error) { return nil, errors.New("addresses unavailable") }
	if _, err := NewAddressPolicy(); err == nil {
		t.Fatal("an interface whose addresses could not be read was skipped silently")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("payload bytes"))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := Acquire(ctx, frozen(t, server.URL+"/dist/demo-1.0.tar.gz"), t.TempDir(), testConfig()); err == nil {
		t.Fatal("acquisition proceeded without a complete address policy")
	}
}
