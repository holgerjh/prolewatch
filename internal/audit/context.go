package audit

import (
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"sort"
)

// Yay context is advisory transaction metadata, not authority. Bound it to
// 64 KiB because it arrives through the hook environment/argument boundary.
const maxYayContextBytes = 64 * 1024

func DecodeYayContext(raw string) (brief.YayContext, error) {
	if raw == "" {
		return brief.YayContext{Packages: []brief.YayPackageContext{}, Depends: []string{}, MakeDepends: []string{}, CheckDepends: []string{}}, nil
	}
	if len(raw) > maxYayContextBytes {
		return brief.YayContext{}, errors.New("yay context exceeds hard input limit")
	}
	var context brief.YayContext
	if err := DecodeStrict([]byte(raw), &context); err != nil {
		return brief.YayContext{}, fmt.Errorf("decode yay context: %w", err)
	}
	if context.Packages == nil || context.Depends == nil || context.MakeDepends == nil || context.CheckDepends == nil {
		return brief.YayContext{}, errors.New("yay context arrays must be present")
	}
	if err := context.Validate(); err != nil {
		return brief.YayContext{}, err
	}
	return context, nil
}

func CompareManifests(previous, current []map[string]any) []brief.ManifestChange {
	// Ignore malformed legacy records rather than letting advisory history break
	// a current scan. The current report still validates its own manifest fully.
	type value struct{ hash string }
	before, after := map[string]value{}, map[string]value{}
	for _, record := range previous {
		if decoded, err := brief.ValidateManifestRecord(record); err == nil && decoded.SHA256 != "" {
			before[decoded.Path] = value{decoded.SHA256}
		}
	}
	for _, record := range current {
		if decoded, err := brief.ValidateManifestRecord(record); err == nil && decoded.SHA256 != "" {
			after[decoded.Path] = value{decoded.SHA256}
		}
	}
	paths := make([]string, 0, len(before)+len(after))
	seen := map[string]bool{}
	for path := range before {
		paths = append(paths, path)
		seen[path] = true
	}
	for path := range after {
		if !seen[path] {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	changes := make([]brief.ManifestChange, 0)
	for _, path := range paths {
		old, oldOK := before[path]
		fresh, freshOK := after[path]
		switch {
		case !oldOK && freshOK:
			changes = append(changes, brief.ManifestChange{Path: path, Status: "added", CurrentSHA256: fresh.hash})
		case oldOK && !freshOK:
			changes = append(changes, brief.ManifestChange{Path: path, Status: "deleted", PreviousSHA256: old.hash})
		case old.hash != fresh.hash:
			changes = append(changes, brief.ManifestChange{Path: path, Status: "changed", PreviousSHA256: old.hash, CurrentSHA256: fresh.hash})
		}
	}
	return changes
}
