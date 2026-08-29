package brief

import (
	"strconv"
	"strings"
)

// One mtree reader, because two partial ones disagreed.
//
// libarchive's mtree output is a small grammar, and the code handled it twice
// without implementing it: the artifact scanner tested for the substring
// "mode=4", and the rewriter cut the pathname at the first space. Both are
// wrong on output the target toolchain actually emits - an ordinary read-only
// file is `mode=400`, and a member named "evil hook.hook" is written
// `./evil\040hook.hook`.

// MTreeRecord is one path line: its decoded pathname and its fields.
type MTreeRecord struct {
	// Path is the pathname with libarchive's escapes decoded, so it can be
	// compared against an archive member name.
	Path string
	// Mode is the octal permission bits, and Explicit says whether the record
	// carried one of its own rather than inheriting the /set default.
	Mode     int64
	Explicit bool
	// Capability reports an xattr granting file capabilities.
	Capability bool
}

// mtreeDefaults tracks the /set and /unset directives a record inherits.
type mtreeDefaults struct {
	mode    int64
	hasMode bool
}

// ParseMTree walks mtree text, applying /set and /unset defaults, and calls
// visit for every path record. A line that cannot be understood is passed to
// visit with Explicit false and Mode -1 rather than being skipped silently:
// this text is package-authored, and "unparsable" must never read as "safe".
func ParseMTree(text string, visit func(index int, line string, record MTreeRecord)) {
	defaults := mtreeDefaults{}
	for index, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if directive, rest, _ := strings.Cut(trimmed, " "); directive == "/set" || directive == "/unset" {
			applyMTreeDirective(&defaults, directive, rest)
			continue
		}
		visit(index, line, parseMTreeRecord(trimmed, defaults))
	}
}

func applyMTreeDirective(defaults *mtreeDefaults, directive, rest string) {
	for _, field := range strings.Fields(rest) {
		key, value, ok := strings.Cut(field, "=")
		if directive == "/unset" {
			key = field
			ok = true
		}
		if !ok || key != "mode" {
			continue
		}
		if directive == "/unset" {
			defaults.mode, defaults.hasMode = 0, false
			continue
		}
		if mode, err := strconv.ParseInt(value, 8, 64); err == nil {
			defaults.mode, defaults.hasMode = mode, true
		}
	}
}

func parseMTreeRecord(line string, defaults mtreeDefaults) MTreeRecord {
	fields := strings.Fields(line)
	record := MTreeRecord{Mode: -1}
	if len(fields) == 0 {
		return record
	}
	record.Path = DecodeMTreePath(fields[0])
	if defaults.hasMode {
		record.Mode = defaults.mode
	}
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch {
		case key == "mode":
			// Octal, as mtree(5) writes it. The old substring test called
			// mode=400 privileged and mode=4755 privileged for the same reason,
			// which is to say for no reason at all.
			if mode, err := strconv.ParseInt(value, 8, 64); err == nil {
				record.Mode, record.Explicit = mode, true
			} else {
				record.Mode, record.Explicit = -1, true
			}
		case strings.HasPrefix(key, "xattr") && strings.Contains(value, "security.capability"),
			key == "security.capability":
			record.Capability = true
		}
	}
	if strings.Contains(line, "security.capability") {
		record.Capability = true
	}
	return record
}

// DecodeMTreePath undoes libarchive's octal escaping of a pathname token.
//
// Comparing the raw token against an archive member name is how a stripped
// member kept its .MTREE record: the archive says "evil hook.hook" and the
// metadata says "./evil\040hook.hook".
func DecodeMTreePath(token string) string {
	if !strings.Contains(token, `\`) {
		return token
	}
	var out strings.Builder
	for index := 0; index < len(token); index++ {
		if token[index] != '\\' || index+3 >= len(token) {
			out.WriteByte(token[index])
			continue
		}
		value, err := strconv.ParseUint(token[index+1:index+4], 8, 8)
		if err != nil {
			out.WriteByte(token[index])
			continue
		}
		out.WriteByte(byte(value))
		index += 3
	}
	return out.String()
}

// MTreePrivileged reports whether a record grants privilege on extraction:
// setuid, setgid, or file capabilities.
func MTreePrivileged(record MTreeRecord) bool {
	return record.Capability || (record.Mode >= 0 && record.Mode&0o6000 != 0)
}
