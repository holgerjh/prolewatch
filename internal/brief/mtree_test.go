package brief

import (
	"strings"
	"testing"
)

// mtreeFromToolchain is the shape `bsdtar --format=mtree` emits with the
// options makepkg uses, captured from the target toolchain: a /set line with
// the common default, escaped pathnames, and modes only where they differ.
const mtreeFromToolchain = `#mtree
/set type=file uid=0 gid=0 mode=644
. time=1787608020.40074602 mode=755 type=dir
./evil\040hook.hook time=1787608020.40227671 size=1 sha256digest=2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881
./normal.sh time=1787608020.39163337 mode=755 size=0
./readonly.conf time=1787608020.36011108 mode=400 size=0
./world-readable.conf time=1787608020.37303269 mode=444 size=0
./writeonly.conf time=1787608020.38226393 mode=200 size=0
`

// TestOrdinaryModesAreNotPrivileged is the false-positive regression.
//
// The check was `strings.Contains(line, "mode=4")`, so mode=400 and mode=444 -
// a read-only file and a world-readable one, both entirely ordinary package
// content - produced a critical hard block that no approval can cross. mode=200
// matched "mode=2" the same way.
func TestOrdinaryModesAreNotPrivileged(t *testing.T) {
	findings := artifactMetadataFindings(".MTREE", mtreeFromToolchain, ".MTREE")
	if len(findings) != 0 {
		t.Fatalf("ordinary package modes were reported as privileged: %#v", findings)
	}
}

// And the property the check exists for still holds, including through the
// /set default that a record with no mode of its own inherits.
func TestPrivilegedModesAreStillHardBlocked(t *testing.T) {
	for name, text := range map[string]string{
		"explicit setuid":    "#mtree\n/set type=file mode=644\n./usr/bin/su mode=4755 size=1\n",
		"explicit setgid":    "#mtree\n/set type=file mode=644\n./usr/bin/wall mode=2755 size=1\n",
		"inherited from set": "#mtree\n/set type=file mode=4755\n./usr/bin/quiet size=1\n",
		"capability xattr":   "#mtree\n/set type=file mode=644\n./usr/bin/ping xattr=security.capability size=1\n",
	} {
		findings := artifactMetadataFindings(".MTREE", text, ".MTREE")
		if len(findings) != 1 || !findings[0].HardBlock || findings[0].RuleID != "mtree-privileged" {
			t.Errorf("%s was not hard-blocked: %#v", name, findings)
		}
	}
	// /unset drops the default again, so a later record is no longer privileged.
	cleared := "#mtree\n/set type=file mode=4755\n/unset mode\n./usr/share/doc/readme size=1\n"
	if findings := artifactMetadataFindings(".MTREE", cleared, ".MTREE"); len(findings) != 0 {
		t.Errorf("/unset did not clear the inherited mode: %#v", findings)
	}
}

// TestEscapedPathnamesDecodeToArchiveMemberNames is the rewrite regression: the
// drop set holds decoded archive member names, and comparing the raw token left
// a stripped member's metadata record behind.
func TestEscapedPathnamesDecodeToArchiveMemberNames(t *testing.T) {
	for token, want := range map[string]string{
		`./evil\040hook.hook`: "./evil hook.hook",
		`./plain.hook`:        "./plain.hook",
		`./tab\011name`:       "./tab\tname",
		`./back\134slash`:     `./back\slash`,
		`./not\09escape`:      `./not\09escape`,
		`./trailing\`:         `./trailing\`,
	} {
		if got := DecodeMTreePath(token); got != want {
			t.Errorf("%q decoded to %q, want %q", token, got, want)
		}
	}
	// End to end: the record for an escaped name normalises to the member name
	// the archive uses, which is what the filter compares against.
	var decoded []string
	ParseMTree(mtreeFromToolchain, func(_ int, _ string, record MTreeRecord) {
		decoded = append(decoded, NormalizeMember(record.Path))
	})
	if !containsString(decoded, "evil hook.hook") {
		t.Fatalf("the escaped member name never reached the drop comparison: %v", decoded)
	}
}

// An unreadable record must not read as a safe one: this text is written by the
// package.
func TestUnparsableModeIsNotTreatedAsSafe(t *testing.T) {
	record := parseMTreeRecord("./x mode=notoctal size=1", mtreeDefaults{})
	if record.Explicit != true || record.Mode != -1 {
		t.Fatalf("an unreadable mode was not marked unknown: %#v", record)
	}
	if strings.Contains(mtreeFromToolchain, "mode=4755") {
		t.Fatal("fixture drifted")
	}
}
