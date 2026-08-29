// Package egress is the network broker and its policy: what the build may
// reach, and how it is asked. It sits above contain and below brief and ui in
// the layering that scripts/check-import-direction.sh enforces.
//
// It is not called net, because a package named net forces every file that
// needs the standard library alongside it into an alias.
package egress

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/holgerjh/prolewatch/internal/contain"
	"github.com/holgerjh/prolewatch/internal/safe"
)

// SourceKind distinguishes what an entry of the source= array can become on
// the wire. The distinction is not cosmetic: an exact-URL match is correct for
// a tarball and wrong for a VCS source, because git's smart HTTP transport
// appends its own paths and query strings to the repository URL.
type SourceKind int

const (
	// SourceLocal is a file already in the checkout. It never reaches the
	// network and is not part of the allowance at all.
	SourceLocal SourceKind = iota
	// SourceExact is fetched as one URL, byte for byte as declared.
	SourceExact
	// SourceVCS is a repository URL the client extends with transport paths,
	// so it is matched as a prefix on the same host.
	SourceVCS
)

// DeclaredSource is one entry of the source= array as makepkg computed it.
type DeclaredSource struct {
	Raw  string // the entry as declared, including any name:: prefix
	URL  string // the fetchable URL, rename prefix and VCS scheme removed
	Kind SourceKind
}

// Allowance is the frozen set of destinations the acquisition phase may reach.
//
// It has no exported fields and exactly one constructor. That is deliberate and
// structural: the architecture requires that the URL set be derived once, from
// a contained evaluation of the PKGBUILD, and then enforced. Allowing another
// constructor could derive it from a more trusting source such as committed
// .SRCINFO. FreezeDeclaredSources is therefore the only construction path.
type Allowance struct {
	sources []DeclaredSource
	// derived is the .SRCINFO text regenerated from the PKGBUILD, kept so the
	// briefing can describe the set that was actually frozen.
	derived []byte
	frozen  time.Time
	origin  string
}

// ErrNotFrozen guards against an Allowance that was never derived.
var ErrNotFrozen = errors.New("source allowance was never frozen")

// FreezeDeclaredSources evaluates the PKGBUILD in the checkout inside
// containment with no network, and freezes the resulting source set.
//
// This is the single owner of "what may the acquisition phase reach". Two
// properties it exists to hold:
//
// The evaluation is contained. makepkg *sources* the PKGBUILD on every
// invocation, --printsrcinfo included, so top-level statements written by the
// package author execute here - before any phase function and before any
// verification. The evaluation therefore runs in the same sandbox as the
// build, with the network namespace empty.
//
// The committed .SRCINFO is not what is frozen. It is maintainer-authored, can
// disagree with the PKGBUILD, and would let a package declare one set of
// sources and fetch another. --printsrcinfo regenerates it from the PKGBUILD
// and ignores any committed copy; that is why it is used instead of parsing the
// file already sitting in the checkout.
//
// DerivedSrcinfo hands those bytes back so the post briefing describes the same
// set. The briefing used to parse the committed file, which meant this freeze
// was honest about its own input while the user was shown another one.
func FreezeDeclaredSources(ctx context.Context, ns *contain.Namespace, checkout string, limits contain.Limits) (*Allowance, error) {
	if ns == nil {
		return nil, errors.New("freeze requires a containment namespace: PKGBUILD evaluation must never run uncontained")
	}
	if _, err := os.Stat(checkout + "/PKGBUILD"); err != nil {
		return nil, fmt.Errorf("no PKGBUILD in %s: %w", checkout, err)
	}
	spec := contain.Spec{
		Workdir: checkout,
		Env:     contain.BaseEnv(),
		Argv:    []string{"/usr/bin/makepkg", "--printsrcinfo"},
	}
	// RunLimited, not Run. This is arbitrary shell under a resource envelope,
	// and its stdout is bounded in the supervisor rather than written to a temp
	// file the package could grow without limit.
	out, errOut, err := contain.RunLimited(ctx, ns, spec, limits)
	if err != nil {
		// makepkg's diagnostics go to stderr and are the only useful signal when
		// a PKGBUILD fails to evaluate. Dropping them turns every authoring error
		// into an opaque exit status.
		if trimmed := strings.TrimSpace(safe.Text(string(errOut), 4000)); trimmed != "" {
			return nil, fmt.Errorf("contained PKGBUILD evaluation: %w\n%s", err, trimmed)
		}
		return nil, fmt.Errorf("contained PKGBUILD evaluation: %w", err)
	}
	sources, err := ParseSrcinfoSources(out)
	if err != nil {
		return nil, err
	}
	return &Allowance{
		sources: sources,
		derived: out,
		frozen:  time.Now(),
		origin:  checkout,
	}, nil
}

// DerivedSrcinfo is the .SRCINFO text this freeze regenerated from the
// PKGBUILD.
//
// It is returned so the briefing can be built from the same bytes the fetch was
// planned from. The alternative - each side parsing its own file - is how the
// user came to be shown the committed .SRCINFO while acquisition used this.
func (a *Allowance) DerivedSrcinfo() []byte {
	if a == nil {
		return nil
	}
	return append([]byte(nil), a.derived...)
}

// ParseSrcinfoSources extracts the source entries from .SRCINFO-format text.
// Exported for the briefing, which shows the user the same set that was frozen
// rather than deriving its own.
// MaxDeclaredSources caps how many distinct sources one package may declare.
//
// The cap exists because everything downstream is per-source: a prompt, a
// fetch, a file in SRCDEST. Fifty thousand declared sources is not a package
// anyone builds; it is a way to turn one PKGBUILD into an unbounded amount of
// trusted-side work. Real packages are far below this - the largest in the AUR
// declare tens - so the limit costs nothing legitimate.
const MaxDeclaredSources = 256

// maxSrcinfoLineBytes bounds a single .SRCINFO line. Anything longer is not a
// source URL.
const maxSrcinfoLineBytes = 64 * 1024

// ParseSrcinfoSources extracts the declared sources from generated .SRCINFO.
//
// It returns an error rather than a partial set. A truncated parse of an
// attacker-authored file is the worst outcome available: the user is shown a
// short list of sources, agrees to it, and the sources that did not fit are
// simply the ones nobody looked at.
func ParseSrcinfoSources(raw []byte) ([]DeclaredSource, error) {
	var sources []DeclaredSource
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), maxSrcinfoLineBytes)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		// Architecture-specific arrays (source_x86_64) count too.
		if key != "source" && !strings.HasPrefix(key, "source_") {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		if len(sources) >= MaxDeclaredSources {
			return nil, fmt.Errorf("PKGBUILD declares more than %d sources", MaxDeclaredSources)
		}
		sources = append(sources, classifySource(value))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading declared sources: %w", err)
	}
	return sources, nil
}

// vcsSchemes are the makepkg source prefixes that denote a version control
// checkout rather than a single file fetch.
var vcsSchemes = []string{"git+", "hg+", "svn+", "bzr+", "fossil+"}

func classifySource(entry string) DeclaredSource {
	source := DeclaredSource{Raw: entry, Kind: SourceLocal}

	// A `name::url` prefix renames the downloaded file; it is not part of the
	// request. Split on the first :: only, since URLs contain colons.
	target := entry
	if _, after, ok := strings.Cut(entry, "::"); ok {
		target = after
	}

	kind := SourceExact
	for _, scheme := range vcsSchemes {
		if strings.HasPrefix(target, scheme) {
			target = strings.TrimPrefix(target, scheme)
			kind = SourceVCS
			break
		}
	}
	// A bare `git://` or `svn://` URL is a VCS source without the + form.
	if parsed, err := url.Parse(target); err == nil {
		switch parsed.Scheme {
		case "git", "svn", "hg", "bzr":
			kind = SourceVCS
		}
	}

	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		// No scheme and no host: a file in the checkout. It is not network.
		return source
	}
	// The fragment selects a VCS ref (#tag=, #commit=) and is never sent.
	parsed.Fragment = ""
	source.Kind = kind
	source.URL = parsed.String()
	return source
}

// Declared returns the frozen source set, for the briefing to display. The
// briefing shows what was frozen; it does not re-derive it.
func (a *Allowance) Declared() []DeclaredSource {
	if a == nil {
		return nil
	}
	out := make([]DeclaredSource, len(a.sources))
	copy(out, a.sources)
	return out
}

// Permits reports whether a request URL is within the frozen allowance.
//
// This is exact-URL matching, and it is usable because the caller is
// Prolewatch's own fetcher, which composes the request itself. It is not, and
// cannot be, a proxy-side check: a proxy sees CONNECT.
//
// Divergence is not an error to recover from by widening: makepkg re-derives
// source= at fetch time, and a PKGBUILD can compute URLs nondeterministically,
// so a request outside the frozen set is an undeclared destination and is
// treated as one. The caller denies or prompts; it never adds to the set.
func (a *Allowance) Permits(rawURL string) (bool, error) {
	if a == nil || a.frozen.IsZero() {
		return false, ErrNotFrozen
	}
	request, err := url.Parse(rawURL)
	if err != nil {
		return false, fmt.Errorf("unparsable request URL %q: %w", rawURL, err)
	}
	for _, source := range a.sources {
		switch source.Kind {
		case SourceLocal:
			continue
		case SourceExact:
			if sameRequest(source.URL, request) {
				return true, nil
			}
		case SourceVCS:
			if underRepository(source.URL, request) {
				return true, nil
			}
		}
	}
	return false, nil
}

// sameRequest compares a declared URL to a request byte for byte, after
// normalising only what cannot carry meaning: the scheme's default port.
func sameRequest(declared string, request *url.URL) bool {
	parsed, err := url.Parse(declared)
	if err != nil {
		return false
	}
	return normalizeHost(parsed) == normalizeHost(request) &&
		parsed.Scheme == request.Scheme &&
		parsed.Path == request.Path &&
		parsed.RawQuery == request.RawQuery
}

// underRepository matches a VCS repository URL as a prefix on the same host.
//
// Exact matching is wrong for these: git's smart HTTP transport requests
// <repo>/info/refs?service=git-upload-pack and POSTs to <repo>/git-upload-pack,
// so an exact-URL allowance would deny every git+https source. The match is
// still tight - same host, same scheme, and a path under the declared
// repository - so it grants no reach beyond the repository the user consented
// to in the briefing.
func underRepository(declared string, request *url.URL) bool {
	parsed, err := url.Parse(declared)
	if err != nil {
		return false
	}
	if normalizeHost(parsed) != normalizeHost(request) || parsed.Scheme != request.Scheme {
		return false
	}
	base := strings.TrimSuffix(parsed.Path, "/")
	if base == "" {
		// A source declared as https://host/ has an empty path prefix, which would
		// match every path on that host. The declaration is underspecified rather
		// than malicious, but a prefix that matches everything is not a prefix
		// match; fall back to the exact request.
		return request.Path == "" || request.Path == "/"
	}
	return request.Path == base || strings.HasPrefix(request.Path, base+"/")
}

func normalizeHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	switch {
	case port == "":
	case u.Scheme == "https" && port == "443":
	case u.Scheme == "http" && port == "80":
	default:
		host += ":" + port
	}
	return host
}
