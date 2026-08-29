// Package contain builds the process containment that Prolewatch runs every
// piece of untrusted package code inside: PKGBUILD evaluation, source
// acquisition, the build itself, and the archive parsing the integration gate
// performs afterwards.
//
// It is the lowest layer in the architecture (contain -> net -> brief -> ui)
// and deliberately imports nothing else from this project, so that a reviewer
// can bound what the containment path can reach by reading this package alone.
// scripts/check-import-direction.sh enforces that.
//
// The construction and its non-obvious constraints are documented in
// docs/architecture.md control 1, and every property asserted here is measured
// by scripts/probes/probe-contained-makepkg.sh and
// scripts/probes/probe-namespace-properties.sh.
package contain

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// subordinate ID ranges are conventionally 65536 entries wide, which is also
// the part of the uid space package archives conventionally express.
const idSpace = 65536

// minDelegation is the narrowest delegation that can still map the whole ID
// space. Ordinary Arch accounts have IDs inside that space and therefore use
// one identity-mapped ID instead of a subordinate ID. Directory-backed and
// otherwise centrally allocated accounts can have a higher ID, though, in
// which case all 65536 archive IDs need subordinate mappings. Requiring the
// conventional full range handles both cases and matches shadow's default.
//
// A narrower delegation is rejected rather than partially mapped. It is
// syntactically valid and gets through every check that looks at one ID at a
// time, and the damage surfaces much later: 65534/nobody is outside the range,
// chown to it returns EINVAL, fakeroot does not absorb EINVAL, and the build
// dies inside somebody else's package() with an ownership error that points
// nowhere near here.
const minDelegation = idSpace

// Linux reserves (uid_t)-1 as an invalid/unmapped ID, so the exclusive end of
// a delegation may reach this value but may not cross it.
const maxSubIDExclusive = uint64(1)<<32 - 1

// SubIDRange is one line of /etc/subuid or /etc/subgid: Count IDs starting at
// Start have been delegated to the invoking account by the administrator.
type SubIDRange struct {
	Start uint32
	Count uint32
}

// ErrNoSubID reports that the invoking account has no subordinate ID
// delegation. Existing accounts and accounts created under older or custom
// policy commonly lack one even when new accounts receive one automatically.
//
// It is returned rather than papered over because the remedy is a one-time
// administrator action and the user must be told exactly what it is, not
// discover it as an EINVAL from inside somebody else's package() function.
var ErrNoSubID = errors.New("no usable subordinate ID range delegated to this account")

// SubIDAdvice is the operator-facing remedy for ErrNoSubID. shadow selects an
// unused uid and gid range under its own database locks and according to the
// administrator's login.defs policy; Prolewatch must never guess a literal
// range from an unlocked snapshot of /etc/subuid and /etc/subgid.
func SubIDAdvice() string {
	return "prolewatch needs subordinate uid and gid ranges to map ID 0 inside the build\n" +
		"sandbox. Without it, package() functions using `install -o root -g root`\n" +
		"fail with EINVAL, which fakeroot cannot absorb.\n\n" +
		"Run this only while this check reports that the delegation is missing:\n\n" +
		"    sudo usermod --add-subids -- \"$(id -un)\"\n\n" +
		"shadow will allocate non-overlapping uid and gid ranges from the system\n" +
		"policy. This authorizes subordinate mappings inside user namespaces; it\n" +
		"does not grant host root or capabilities in the initial namespace. Then\n" +
		"run `prolewatch doctor` again before setup."
}

// LookupSubIDs returns the subordinate uid and gid ranges delegated to the
// current account, or ErrNoSubID.
func LookupSubIDs() (uidRange, gidRange SubIDRange, err error) {
	if err := requireFileSubIDProvider("/etc/nsswitch.conf"); err != nil {
		return SubIDRange{}, SubIDRange{}, err
	}
	self, err := user.Current()
	if err != nil {
		return SubIDRange{}, SubIDRange{}, fmt.Errorf("resolve current user: %w", err)
	}
	uidRange, uerr := lookupSubIDFile("/etc/subuid", self.Username, self.Uid, self.Uid)
	// /etc/subgid is keyed by login name or uid, not by the user's primary gid.
	// The mapped host identity is still the gid, so those are separate inputs.
	gidRange, gerr := lookupSubIDFile("/etc/subgid", self.Username, self.Uid, self.Gid)
	if uerr != nil {
		return SubIDRange{}, SubIDRange{}, uerr
	}
	if gerr != nil {
		return SubIDRange{}, SubIDRange{}, gerr
	}
	return uidRange, gidRange, nil
}

// requireFileSubIDProvider makes the implementation boundary explicit. The
// subid database may be supplied by an NSS plugin, but parsing /etc/subuid and
// /etc/subgid while newuidmap consults a different authority would validate one
// delegation and use another. An absent subid line means the documented files
// fallback and is accepted.
func requireFileSubIDProvider(path string) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "subid:" {
			continue
		}
		if len(fields) == 2 && fields[1] == "files" {
			return nil
		}
		return fmt.Errorf("unsupported subordinate-ID provider in %s: %q; prolewatch currently supports only `subid: files`", path, strings.Join(fields[1:], " "))
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

type subIDEntry struct {
	owner string
	ids   SubIDRange
	line  int
}

func subIDEnd(r SubIDRange) (uint64, error) {
	end := uint64(r.Start) + uint64(r.Count)
	if r.Count == 0 || end > maxSubIDExclusive {
		return 0, fmt.Errorf("range %d+%d crosses the maximum mappable ID", r.Start, r.Count)
	}
	return end, nil
}

func subIDRangesOverlap(a, b SubIDRange) bool {
	aEnd, aErr := subIDEnd(a)
	bEnd, bErr := subIDEnd(b)
	return aErr == nil && bErr == nil && uint64(a.Start) < bEnd && uint64(b.Start) < aEnd
}

// lookupSubIDFile parses one of the subordinate ID files. Entries may be keyed
// by name or by numeric ID; both forms are accepted because both are written in
// practice by different tools.
func lookupSubIDFile(path, username, numericOwnerID, mappedID string) (SubIDRange, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return SubIDRange{}, fmt.Errorf("%w: %s does not exist", ErrNoSubID, path)
		}
		return SubIDRange{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	var entries []subIDEntry
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 3 {
			return SubIDRange{}, fmt.Errorf("%s:%d is not a valid subordinate-ID entry", path, lineNumber)
		}
		start, err1 := strconv.ParseUint(fields[1], 10, 32)
		count, err2 := strconv.ParseUint(fields[2], 10, 32)
		if err1 != nil || err2 != nil || count == 0 {
			return SubIDRange{}, fmt.Errorf("%s:%d has an invalid subordinate-ID range", path, lineNumber)
		}
		ids := SubIDRange{Start: uint32(start), Count: uint32(count)}
		if _, err := subIDEnd(ids); err != nil {
			return SubIDRange{}, fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
		entries = append(entries, subIDEntry{owner: fields[0], ids: ids, line: lineNumber})
	}
	if err := scanner.Err(); err != nil {
		return SubIDRange{}, fmt.Errorf("read %s: %w", path, err)
	}
	isCurrentOwner := func(owner string) bool { return owner == username || owner == numericOwnerID }
	var own []subIDEntry
	for _, entry := range entries {
		if isCurrentOwner(entry.owner) {
			own = append(own, entry)
		}
	}
	if len(own) == 0 {
		return SubIDRange{}, fmt.Errorf("%w: no entry for %s in %s", ErrNoSubID, username, path)
	}

	// Overlap is not merely untidy: two accounts able to map the same host ID
	// can access each other's namespaced files. Check every range delegated to
	// this account, including a narrow range Prolewatch itself would not select.
	for _, candidate := range own {
		for _, other := range entries {
			if isCurrentOwner(other.owner) || !subIDRangesOverlap(candidate.ids, other.ids) {
				continue
			}
			return SubIDRange{}, fmt.Errorf("unsafe subordinate-ID overlap in %s: %s at line %d (%d+%d) overlaps %s at line %d (%d+%d)",
				path, candidate.owner, candidate.line, candidate.ids.Start, candidate.ids.Count,
				other.owner, other.line, other.ids.Start, other.ids.Count)
		}
	}

	mapped, err := strconv.ParseUint(mappedID, 10, 32)
	if err != nil {
		return SubIDRange{}, fmt.Errorf("parse invoking ID %q for %s: %w", mappedID, path, err)
	}
	best := SubIDRange{}
	for _, candidate := range own {
		end, _ := subIDEnd(candidate.ids)
		if uint64(candidate.ids.Start) <= mapped && mapped < end {
			return SubIDRange{}, fmt.Errorf("unsafe subordinate-ID delegation in %s: %s's range %d+%d contains its identity-mapped host ID %d",
				path, candidate.owner, candidate.ids.Start, candidate.ids.Count, mapped)
		}
		// Multiple delegations are legal. Take the widest; the width check
		// below then applies to the best one on offer.
		if candidate.ids.Count > best.Count {
			best = candidate.ids
		}
	}
	if best.Count < minDelegation {
		return SubIDRange{}, fmt.Errorf("%w: %s delegates %d IDs to %s, and %d are needed to map the whole namespace ID space",
			ErrNoSubID, path, best.Count, username, minDelegation)
	}
	return best, nil
}
