package audit

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const maxYayContextBytes = 64 * 1024

type YayPackageContext struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	LocalVersion string `json:"local_version"`
	Reason       string `json:"reason"`
	Upgrade      bool   `json:"upgrade"`
	Devel        bool   `json:"devel"`
}

type YayContext struct {
	Version      string              `json:"version"`
	LastModified int64               `json:"last_modified"`
	Installed    bool                `json:"installed"`
	Packages     []YayPackageContext `json:"packages"`
	Depends      []string            `json:"depends"`
	MakeDepends  []string            `json:"makedepends"`
	CheckDepends []string            `json:"checkdepends"`
}

func (c YayContext) Validate() error {
	if len(c.Version) > 256 || c.LastModified < 0 || len(c.Packages) > 128 ||
		len(c.Depends) > 4096 || len(c.MakeDepends) > 4096 || len(c.CheckDepends) > 4096 {
		return errors.New("yay context exceeds value limits")
	}
	reasons := map[string]bool{"explicit": true, "dependency": true, "make_dependency": true, "check_dependency": true, "unknown": true, "": true}
	seenPackages := map[string]bool{}
	for _, pkg := range c.Packages {
		if ValidatePackageBase(pkg.Name) != nil || seenPackages[pkg.Name] || len(pkg.Version) > 256 || len(pkg.LocalVersion) > 256 || !reasons[pkg.Reason] {
			return fmt.Errorf("invalid yay package context for %q", pkg.Name)
		}
		seenPackages[pkg.Name] = true
	}
	for _, values := range [][]string{c.Depends, c.MakeDepends, c.CheckDepends} {
		seen := map[string]bool{}
		for _, value := range values {
			if value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") || seen[value] {
				return errors.New("invalid or duplicate yay dependency context")
			}
			seen[value] = true
		}
	}
	return nil
}

func DecodeYayContext(raw string) (YayContext, error) {
	if raw == "" {
		return YayContext{Packages: []YayPackageContext{}, Depends: []string{}, MakeDepends: []string{}, CheckDepends: []string{}}, nil
	}
	if len(raw) > maxYayContextBytes {
		return YayContext{}, errors.New("yay context exceeds hard input limit")
	}
	var context YayContext
	if err := DecodeStrict([]byte(raw), &context); err != nil {
		return YayContext{}, fmt.Errorf("decode yay context: %w", err)
	}
	if context.Packages == nil || context.Depends == nil || context.MakeDepends == nil || context.CheckDepends == nil {
		return YayContext{}, errors.New("yay context arrays must be present")
	}
	if err := context.Validate(); err != nil {
		return YayContext{}, err
	}
	return context, nil
}

type ManifestChange struct {
	Path           string `json:"path"`
	Status         string `json:"status"`
	PreviousSHA256 string `json:"previous_sha256,omitempty"`
	CurrentSHA256  string `json:"current_sha256,omitempty"`
}

func (c ManifestChange) Validate() error {
	if c.Path == "" || len(c.Path) > 4096 || (c.Status != "added" && c.Status != "changed" && c.Status != "deleted") {
		return errors.New("invalid manifest change")
	}
	switch c.Status {
	case "added":
		if c.PreviousSHA256 != "" || !validHexDigest(c.CurrentSHA256) {
			return errors.New("invalid added manifest change")
		}
	case "deleted":
		if !validHexDigest(c.PreviousSHA256) || c.CurrentSHA256 != "" {
			return errors.New("invalid deleted manifest change")
		}
	case "changed":
		if !validHexDigest(c.PreviousSHA256) || !validHexDigest(c.CurrentSHA256) || c.PreviousSHA256 == c.CurrentSHA256 {
			return errors.New("invalid changed manifest change")
		}
	}
	return nil
}

func CompareManifests(previous, current []map[string]any) []ManifestChange {
	type value struct{ hash string }
	before, after := map[string]value{}, map[string]value{}
	for _, record := range previous {
		if decoded, err := validateManifestRecord(record); err == nil && decoded.SHA256 != "" {
			before[decoded.Path] = value{decoded.SHA256}
		}
	}
	for _, record := range current {
		if decoded, err := validateManifestRecord(record); err == nil && decoded.SHA256 != "" {
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
	changes := make([]ManifestChange, 0)
	for _, path := range paths {
		old, oldOK := before[path]
		fresh, freshOK := after[path]
		switch {
		case !oldOK && freshOK:
			changes = append(changes, ManifestChange{Path: path, Status: "added", CurrentSHA256: fresh.hash})
		case oldOK && !freshOK:
			changes = append(changes, ManifestChange{Path: path, Status: "deleted", PreviousSHA256: old.hash})
		case old.hash != fresh.hash:
			changes = append(changes, ManifestChange{Path: path, Status: "changed", PreviousSHA256: old.hash, CurrentSHA256: fresh.hash})
		}
	}
	return changes
}
