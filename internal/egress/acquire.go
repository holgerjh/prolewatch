package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// newAddressPolicy is a seam so tests can exercise the real fetch path against
// a loopback server. Production always uses the real policy.
var newAddressPolicy = NewAddressPolicy

// maxRedirectHops bounds a declared fetch's redirect chain.
// probe-redirect-chains.sh measured real chains at one hop; five leaves room
// for registry topology to change without leaving a loop unbounded.
const maxRedirectHops = 5

// FetchRecord is what one declared source actually did on the wire. It exists
// for the transaction report: observed hop chains are worth seeing, and are
// deliberately not worth prompting about, because they drift benignly and a
// line nobody can act on trains people to ignore lines.
type FetchRecord struct {
	Declared string
	Filename string
	Hosts    []string // every host contacted, in order, including redirect hops
	Bytes    int64
}

// Acquisition is the result of the trusted-side fetch.
type Acquisition struct {
	Fetched []FetchRecord
	// Declared is the source set from the same contained PKGBUILD evaluation
	// this acquisition enforced. It is retained for trusted prompt explanation;
	// callers must not use it as a second authority path.
	Declared []DeclaredSource
	// VCSHosts are the hosts makepkg itself must still reach, because a
	// version-control checkout is a protocol conversation rather than a fetch.
	VCSHosts []string
}

// AcquisitionProgress is measured trusted-side HTTP transfer progress. Total
// is zero when the server supplied no usable Content-Length; callers must not
// invent a percentage in that case. BytesPerSecond is the running average for
// this source, not an instantaneous promise about future throughput.
type AcquisitionProgress struct {
	Filename       string
	SourceIndex    int
	SourceCount    int
	Bytes          int64
	Total          int64
	BytesPerSecond int64
	Complete       bool
}

type ProgressFunc func(AcquisitionProgress)

// Hosts is every host contacted during acquisition, deduplicated and sorted,
// for the transaction report.
func (a *Acquisition) Hosts() []string {
	seen := map[string]bool{}
	var hosts []string
	for _, record := range a.Fetched {
		for _, host := range record.Hosts {
			if !seen[host] {
				seen[host] = true
				hosts = append(hosts, host)
			}
		}
	}
	for _, host := range a.VCSHosts {
		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return hosts
}

// Acquire fetches every declared non-VCS source into srcdest, using Prolewatch's
// own HTTP client, before any package code runs.
//
// A proxy cannot enforce an exact URL allowance for HTTPS: CONNECT exposes the
// host and port but not the path. Trusted-side fetching keeps URL-granular
// enforcement at the component that composes and can inspect the request.
//
// Fetching from trusted code is exact by construction: the request is the
// declared URL because this code composes it. Three consequences follow:
//
//   - The acquisition window stops being an execution window. makepkg sources
//     the PKGBUILD on every invocation, so author-written shell runs during
//     retrieval; with the sources already present, that shell runs with zero
//     egress. A package with no VCS sources never has an open network while its
//     own code executes.
//   - Divergence fails closed structurally. A PKGBUILD can compute source= a
//     second time and produce different URLs. makepkg then finds no matching
//     file and aborts with no network to reach. There is no allowance to widen
//     and no policy decision to get wrong.
//   - The request-count-and-timing channel closes. The fetcher's requests are a
//     function of the frozen list alone, not of anything package code does.
//
// Fetching an attacker-chosen URL from trusted code grants the attacker
// nothing: the URL was consented to at the briefing, this client sends no
// credentials, and the bytes land in the same untrusted workdir either way.
func Acquire(ctx context.Context, allowance *Allowance, srcdest string, cfg Config) (*Acquisition, error) {
	return AcquireWithProgress(ctx, allowance, srcdest, cfg, nil)
}

// AcquireWithProgress is Acquire with measured transfer updates. The callback
// observes display metadata only and grants no authority over destinations or
// bytes; acquisition still reads exclusively from the frozen allowance.
func AcquireWithProgress(ctx context.Context, allowance *Allowance, srcdest string, cfg Config, progress ProgressFunc) (*Acquisition, error) {
	if allowance == nil || allowance.frozen.IsZero() {
		return nil, ErrNotFrozen
	}
	if err := os.MkdirAll(srcdest, 0o700); err != nil {
		return nil, err
	}
	policy, err := newAddressPolicy()
	if err != nil {
		return nil, err
	}
	budget := newAcquisitionBudget(cfg, srcdest)
	declared := allowance.Declared()
	result := &Acquisition{Declared: declared}
	downloadCount := 0
	for _, source := range declared {
		if source.Kind == SourceExact {
			downloadCount++
		}
	}
	downloadIndex := 0

	for _, source := range declared {
		switch source.Kind {
		case SourceLocal:
			continue
		case SourceVCS:
			parsed, err := url.Parse(source.URL)
			if err != nil || parsed.Host == "" {
				return nil, fmt.Errorf("undeclarable VCS source %q", source.Raw)
			}
			result.VCSHosts = append(result.VCSHosts, strings.ToLower(parsed.Hostname()))
			continue
		}
		downloadIndex++
		// Assert the frozen-set membership immediately before fetching. The loop
		// reads that set directly, but keeping the check at the network boundary
		// prevents any alternative URL source from bypassing the invariant.
		if permitted, err := allowance.Permits(source.URL); err != nil || !permitted {
			return nil, fmt.Errorf("refusing to fetch %q: not in the frozen source set", source.URL)
		}
		record, err := fetchDeclared(ctx, source, srcdest, policy, cfg, budget, progress, downloadIndex, downloadCount)
		if err != nil {
			return nil, fmt.Errorf("acquire %s: %w", source.Raw, err)
		}
		result.Fetched = append(result.Fetched, record)
	}
	result.VCSHosts = dedupeSorted(result.VCSHosts)
	return result, nil
}

type acquisitionProgressWriter struct {
	output      io.Writer
	progress    ProgressFunc
	status      AcquisitionProgress
	started     time.Time
	lastReport  time.Time
	written     int64
	reportEvery time.Duration
}

func (w *acquisitionProgressWriter) Write(value []byte) (int, error) {
	n, err := w.output.Write(value)
	w.written += int64(n)
	w.report(false)
	return n, err
}

func (w *acquisitionProgressWriter) report(force bool) {
	if w.progress == nil {
		return
	}
	now := time.Now()
	if !force && !w.lastReport.IsZero() && now.Sub(w.lastReport) < w.reportEvery {
		return
	}
	status := w.status
	status.Bytes = w.written
	if elapsed := now.Sub(w.started); elapsed > 0 {
		status.BytesPerSecond = int64(float64(w.written) / elapsed.Seconds())
	}
	w.progress(status)
	w.lastReport = now
}

// SourceFilename is the name makepkg expects a downloaded source to have: the
// explicit rename when the entry uses name::url, otherwise the last path
// segment of the URL. Getting this wrong means makepkg re-downloads, which with
// no network means the build fails - loudly, but for a confusing reason.
func SourceFilename(source DeclaredSource) (string, error) {
	if before, _, ok := strings.Cut(source.Raw, "::"); ok && before != "" {
		return validSourceFilename(before)
	}
	parsed, err := url.Parse(source.URL)
	if err != nil {
		return "", err
	}
	return validSourceFilename(path.Base(parsed.Path))
}

// validSourceFilename refuses anything that is not a plain name. The value is
// attacker-authored and is about to become a path, so traversal and separators
// are rejected rather than sanitised.
func validSourceFilename(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || name == "/" ||
		strings.ContainsAny(name, "/\\\x00") {
		return "", fmt.Errorf("source filename %q is not a plain name", name)
	}
	return name, nil
}

// acquisitionBudget is the whole transaction's allowance, not one source's.
//
// The byte budget and deadline are shared by every fetch in the transaction;
// applying either per source would multiply the documented limit by the number
// of declared sources. The source count is capped separately at parse time.
type acquisitionBudget struct {
	remaining int64
	deadline  time.Time
	idle      time.Duration
	reserve   int64
	root      string
}

func newAcquisitionBudget(cfg Config, srcdest string) *acquisitionBudget {
	bytes := cfg.MaxTransferBytes
	if bytes <= 0 {
		bytes = 8 * 1024 * 1024 * 1024
	}
	idle := time.Duration(cfg.IdleTimeoutSeconds) * time.Second
	if idle <= 0 {
		idle = 60 * time.Second
	}
	// Acquisition is trusted-side work with no user watching a prompt, so it
	// gets a wall-clock ceiling of its own. A server that trickles one byte per
	// idle period would otherwise never stall and never finish.
	total := time.Duration(maxDeclaredSources()) * idle
	if total > 2*time.Hour {
		total = 2 * time.Hour
	}
	if total < 10*time.Minute {
		total = 10 * time.Minute
	}
	return &acquisitionBudget{
		remaining: bytes,
		deadline:  time.Now().Add(total),
		idle:      idle,
		reserve:   cfg.DiskReserveBytes,
		root:      srcdest,
	}
}

func maxDeclaredSources() int { return MaxDeclaredSources }

// checkReserve refuses to keep filling a filesystem that is running out.
//
// SRCDEST lives under the user's state directory, outside the monitored
// worktree, so the build's workspace accounting never saw these bytes. Filling
// the filesystem from here is collateral damage on the whole machine, not just
// on the build.
// headroom is how many bytes may still be written before the reserve is
// reached, and whether the filesystem could be measured at all.
// acquisitionStatfs is a seam: the interesting case is a transfer that starts
// above the reserve and would cross it partway through, which cannot be staged
// on a real filesystem without filling one.
var acquisitionStatfs = unix.Statfs

func (b *acquisitionBudget) headroom() (int64, bool) {
	if b.root == "" {
		return 0, false
	}
	var stat unix.Statfs_t
	if err := acquisitionStatfs(b.root, &stat); err != nil {
		return 0, false
	}
	total := int64(stat.Blocks) * stat.Bsize
	available := int64(stat.Bavail) * stat.Bsize
	reserve := b.reserve
	if tenth := total / 10; tenth > reserve {
		reserve = tenth
	}
	return available - reserve, true
}

func (b *acquisitionBudget) checkReserve() error {
	if b.root == "" {
		return nil
	}
	var stat unix.Statfs_t
	if err := acquisitionStatfs(b.root, &stat); err != nil {
		return nil // an unreadable filesystem is not evidence of exhaustion
	}
	total := int64(stat.Blocks) * stat.Bsize
	available := int64(stat.Bavail) * stat.Bsize
	// Whichever is larger: the configured reserve or 10% of this filesystem.
	// Same rule as the build workspace, deliberately.
	reserve := b.reserve
	if tenth := total / 10; tenth > reserve {
		reserve = tenth
	}
	if available < reserve {
		return fmt.Errorf("source filesystem reserve violated: available=%d required=%d", available, reserve)
	}
	return nil
}

func (b *acquisitionBudget) remainingTime() (time.Duration, error) {
	left := time.Until(b.deadline)
	if left <= 0 {
		return 0, errors.New("acquisition exceeded its total time budget")
	}
	return left, nil
}

// stallGuard fails a transfer that stops making progress.
//
// Without it, a response body that sends nothing and never closes holds the
// acquisition open indefinitely: there is no HTTP timeout that covers a
// connection which is healthy at the TCP level and simply silent.
type stallGuard struct {
	body    io.ReadCloser
	timer   *time.Timer
	idle    time.Duration
	stalled atomic.Bool
}

func newStallGuard(body io.ReadCloser, idle time.Duration) *stallGuard {
	guard := &stallGuard{body: body, idle: idle}
	guard.timer = time.AfterFunc(idle, func() {
		guard.stalled.Store(true)
		// Closing the body is what unblocks a Read that is parked in the
		// kernel; a flag alone would never be observed.
		_ = body.Close()
	})
	return guard
}

func (g *stallGuard) Read(p []byte) (int, error) {
	n, err := g.body.Read(p)
	if n > 0 {
		g.timer.Reset(g.idle)
	}
	if g.stalled.Load() {
		return n, fmt.Errorf("source stalled for more than %s", g.idle)
	}
	return n, err
}

func (g *stallGuard) Close() error {
	g.timer.Stop()
	return g.body.Close()
}

func fetchDeclared(ctx context.Context, source DeclaredSource, srcdest string, policy *AddressPolicy, cfg Config, budget *acquisitionBudget, progress ProgressFunc, sourceIndex, sourceCount int) (FetchRecord, error) {
	filename, err := SourceFilename(source)
	if err != nil {
		return FetchRecord{}, err
	}
	record := FetchRecord{Declared: source.URL, Filename: filename}

	parsed, err := url.Parse(source.URL)
	if err != nil {
		return record, err
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		// makepkg supports ftp and others; Prolewatch does not fetch them
		// rather than carrying a second transport with its own address policy.
		return record, fmt.Errorf("unsupported source scheme %q", parsed.Scheme)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext:       checkedDialer(policy, cfg),
			DisableKeepAlives: true,
			// Without this, net/http adds Accept-Encoding: gzip on its own and
			// transparently decodes the reply, so what lands on disk is not what
			// the server sent. makepkg's DLAGENT is curl without --compressed and
			// performs no such transformation, and the file it would have written
			// is the one the PKGBUILD's checksum was computed over. The broker
			// disables it for the same reason.
			DisableCompression:  true,
			TLSHandshakeTimeout: time.Duration(cfg.ConnectTimeoutSeconds) * time.Second,
		},
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirectHops {
				return fmt.Errorf("redirect chain exceeded %d hops", maxRedirectHops)
			}
			// Hops are accepted transitively via a declared fetch's redirect
			// because registry redirect topology can change independently of the
			// package declaration. The address check is not transitive: every hop
			// is dialled through checkedDialer, so a redirect into private or
			// link-local space is refused at connect time regardless of who sent it.
			//
			// The client attaches no credentials at any hop, so there is nothing
			// for a redirect to carry anywhere.
			record.Hosts = append(record.Hosts, strings.ToLower(request.URL.Hostname()))
			return nil
		},
	}
	if err := budget.checkReserve(); err != nil {
		return record, err
	}
	left, err := budget.remainingTime()
	if err != nil {
		return record, err
	}
	// One fetch may not outlive the transaction's remaining time.
	fetchCtx, cancelFetch := context.WithTimeout(ctx, left)
	defer cancelFetch()
	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, source.URL, nil)
	if err != nil {
		return record, err
	}
	request.Header.Set("User-Agent", "prolewatch")
	record.Hosts = append(record.Hosts, strings.ToLower(parsed.Hostname()))

	response, err := client.Do(request)
	if err != nil {
		return record, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return record, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	total := response.ContentLength
	if total < 0 {
		total = 0
	}
	status := AcquisitionProgress{Filename: filename, SourceIndex: sourceIndex, SourceCount: sourceCount, Total: total}
	if progress != nil {
		progress(status)
	}

	target := filepath.Join(srcdest, filename)
	file, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return record, err
	}
	// The budget is what remains for the whole transaction, not a per-source
	// allowance. Reading one byte past it is what makes exhaustion detectable
	// rather than merely truncating the file at the limit.
	limit := budget.remaining
	// The reserve has to bound the transfer, not just precede it. Checking free
	// space once and then copying up to the whole transfer budget made
	// "the free space acquisition must leave" a statement about the moment
	// before the request: with 6 GiB free, a 2 GiB reserve and an 8 GiB
	// per-source budget, one attacker-controlled response could still run the
	// filesystem to ENOSPC and only afterwards have its partial file removed.
	// Removing it returns the blocks; it does not return the writes other
	// processes lost meanwhile.
	reserveBound := false
	if headroom, measured := budget.headroom(); measured && headroom < limit {
		limit, reserveBound = max(headroom, 0), true
	}
	guard := newStallGuard(response.Body, budget.idle)
	progressOutput := &acquisitionProgressWriter{output: file, progress: progress, status: status, started: time.Now(), reportEvery: 250 * time.Millisecond}
	written, copyErr := io.Copy(progressOutput, io.LimitReader(guard, limit+1))
	progressOutput.report(true)
	_ = guard.Close()
	closeErr := file.Close()
	budget.remaining -= written
	if budget.remaining < 0 {
		budget.remaining = 0
	}
	// Every failure path removes the partial file. Leaving it behind would hand
	// makepkg a truncated source that its checksum then rejects for a reason
	// nobody can trace back to here.
	if copyErr != nil {
		os.Remove(target)
		return record, copyErr
	}
	if closeErr != nil {
		os.Remove(target)
		return record, closeErr
	}
	if written > limit {
		os.Remove(target)
		if reserveBound {
			return record, fmt.Errorf("source filesystem reserve reached after %d bytes; refusing to fill it further", limit)
		}
		return record, fmt.Errorf("declared sources exceed the %d byte acquisition budget", limit)
	}
	record.Bytes = written
	record.Hosts = dedupeSorted(record.Hosts)
	if progress != nil {
		status.Bytes = written
		if elapsed := time.Since(progressOutput.started); elapsed > 0 {
			status.BytesPerSecond = int64(float64(written) / elapsed.Seconds())
		}
		status.Complete = true
		progress(status)
	}
	return record, nil
}

// checkedDialer resolves the destination once, refuses the whole answer if any
// address is non-public, and dials an address it checked.
//
// Resolving a second time after the check would be a DNS-rebinding TOCTOU: the
// answer that passed would not be the answer dialled. This mirrors the broker's
// dialPublic deliberately - same policy object, same single-resolution rule.
func checkedDialer(policy *AddressPolicy, cfg Config) func(context.Context, string, string) (net.Conn, error) {
	timeout := time.Duration(cfg.ConnectTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil || !policy.Port(port) {
			return nil, errors.New("port denied")
		}
		resolveCtx, cancel := context.WithTimeout(ctx, timeout)
		addresses, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
		cancel()
		if err != nil || len(addresses) == 0 {
			return nil, errors.New("DNS resolution failed")
		}
		for _, candidate := range addresses {
			if !policy.Public(candidate.IP) {
				return nil, errors.New("DNS answer contains a non-public address")
			}
		}
		dialer := net.Dialer{Timeout: timeout}
		for _, candidate := range addresses {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), portText))
			if err == nil {
				return conn, nil
			}
		}
		return nil, errors.New("all public destinations failed")
	}
}

func dedupeSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
