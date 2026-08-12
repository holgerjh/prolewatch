package audit

import (
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

//go:embed threat-bundle.json
var embeddedThreatBundle []byte

type ThreatEntry struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Ecosystem   string `json:"ecosystem"`
	Value       string `json:"value"`
	Disposition string `json:"disposition"`
	SourceURL   string `json:"source_url"`
	FirstSeen   string `json:"first_seen"`
}

type ThreatBundle struct {
	SchemaVersion int           `json:"schema_version"`
	BundleVersion string        `json:"bundle_version"`
	ReviewedAt    string        `json:"reviewed_at"`
	Entries       []ThreatEntry `json:"entries"`

	ecosystemPackages map[string]ThreatEntry
}

type ThreatBundleIdentity struct {
	SchemaVersion int    `json:"schema_version"`
	BundleVersion string `json:"bundle_version"`
	ReviewedAt    string `json:"reviewed_at"`
	SHA256        string `json:"sha256"`
}

var threatIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)

func LoadEmbeddedThreatBundle() (*ThreatBundle, error) {
	var bundle ThreatBundle
	if err := DecodeStrict(embeddedThreatBundle, &bundle); err != nil {
		return nil, fmt.Errorf("decode embedded threat bundle: %w", err)
	}
	if bundle.SchemaVersion != 1 || !threatIDRE.MatchString(bundle.BundleVersion) {
		return nil, errors.New("invalid embedded threat bundle version")
	}
	if _, err := time.Parse(time.RFC3339, bundle.ReviewedAt); err != nil {
		return nil, errors.New("invalid embedded threat bundle review time")
	}
	if len(bundle.Entries) == 0 || len(bundle.Entries) > 10000 {
		return nil, errors.New("embedded threat bundle has an invalid entry count")
	}
	seen := make(map[string]bool, len(bundle.Entries))
	bundle.ecosystemPackages = make(map[string]ThreatEntry)
	for _, entry := range bundle.Entries {
		if !threatIDRE.MatchString(entry.ID) || seen[entry.ID] || entry.Kind != "ecosystem_package" ||
			entry.Ecosystem == "" || entry.Value == "" || entry.Disposition != "hard_block" {
			return nil, fmt.Errorf("invalid embedded threat entry %q", entry.ID)
		}
		parsed, err := url.Parse(entry.SourceURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return nil, fmt.Errorf("invalid provenance URL for threat entry %q", entry.ID)
		}
		if _, err := time.Parse("2006-01-02", entry.FirstSeen); err != nil {
			return nil, fmt.Errorf("invalid first_seen for threat entry %q", entry.ID)
		}
		key := strings.ToLower(entry.Ecosystem) + "\x00" + strings.ToLower(entry.Value)
		if _, exists := bundle.ecosystemPackages[key]; exists {
			return nil, fmt.Errorf("duplicate threat value for entry %q", entry.ID)
		}
		seen[entry.ID] = true
		bundle.ecosystemPackages[key] = entry
	}
	return &bundle, nil
}

func EmbeddedThreatBundleIdentity() (ThreatBundleIdentity, error) {
	bundle, err := LoadEmbeddedThreatBundle()
	if err != nil {
		return ThreatBundleIdentity{}, err
	}
	return ThreatBundleIdentity{
		SchemaVersion: bundle.SchemaVersion,
		BundleVersion: bundle.BundleVersion,
		ReviewedAt:    bundle.ReviewedAt,
		SHA256:        SHA256Bytes(embeddedThreatBundle),
	}, nil
}

func (b *ThreatBundle) ecosystemPackage(ecosystem, value string) (ThreatEntry, bool) {
	if b == nil {
		return ThreatEntry{}, false
	}
	entry, ok := b.ecosystemPackages[strings.ToLower(ecosystem)+"\x00"+strings.ToLower(packageIdentity(value))]
	return entry, ok
}

func packageIdentity(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "'\"`,")
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "@") {
		if slash := strings.IndexByte(value, '/'); slash >= 0 {
			if version := strings.IndexByte(value[slash+1:], '@'); version >= 0 {
				return value[:slash+1+version]
			}
		}
		return value
	}
	if version := strings.IndexByte(value, '@'); version >= 0 {
		value = value[:version]
	}
	return value
}

func threatFinding(path string, line int, entry ThreatEntry, evidence string) Finding {
	lineCopy := line
	return Finding{
		Severity:  "critical",
		Category:  "remote_execution",
		File:      path,
		Line:      &lineCopy,
		Evidence:  truncate(evidence, 320),
		Rationale: "exact package identifier matches reviewed threat intelligence " + entry.ID,
		RuleID:    "threat-" + entry.ID,
		HardBlock: true,
	}
}
