package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const markerPrefix = ".prolewatch-"

var importantNames = map[string]bool{
	"PKGBUILD": true, ".SRCINFO": true, "Makefile": true, "CMakeLists.txt": true,
	"meson.build": true, "build.rs": true, "setup.py": true, "pyproject.toml": true, "package.json": true,
	"package-lock.json": true, "npm-shrinkwrap.json": true, ".npmrc": true, "Cargo.toml": true,
	"go.mod": true, "pip.conf": true,
}
var importantSuffixes = map[string]bool{
	".install": true, ".patch": true, ".diff": true, ".sh": true, ".bash": true, ".zsh": true, ".py": true,
	".pl": true, ".rb": true, ".js": true, ".ts": true, ".lua": true, ".service": true, ".socket": true,
	".timer": true, ".path": true, ".rules": true, ".hook": true, ".desktop": true, ".conf": true,
}

type Scanner struct {
	Config Config
	Rules  RuleEngine
}

// makepkgArchiveProber is a process-boundary seam. Production always uses the
// Bubblewrap-isolated bsdtar probe; hermetic tests replace it because nested
// user namespaces are intentionally unavailable on many CI container hosts.
var makepkgArchiveProber = probeMakepkgArchive

var ErrScannerTimeout = errors.New("scanner transaction timed out")

type scanProgressFunc func(ActivityScanProgress, bool)

type scanOptions struct {
	bindingOnly bool
}

type scannerProgressEmitter struct {
	inv      *Inventory
	callback scanProgressFunc
}

func (e *scannerProgressEmitter) emit(operation string, force bool) {
	if e == nil || e.callback == nil || e.inv == nil {
		return
	}
	e.callback(ActivityScanProgress{Operation: operation, FilesSeen: e.inv.Coverage.FilesSeen,
		BytesSeen: e.inv.Coverage.BytesSeen, ArchivesSeen: e.inv.Coverage.ArchivesSeen,
		ArchiveEntries: e.inv.Coverage.ArchiveEntries}, force)
}

func (e *scannerProgressEmitter) emitArchive(progress ArchiveProgress) {
	if e == nil || e.callback == nil || e.inv == nil {
		return
	}
	e.callback(ActivityScanProgress{Operation: ScanOperationArchiveInspection, FilesSeen: e.inv.Coverage.FilesSeen,
		BytesSeen: e.inv.Coverage.BytesSeen, ArchivesSeen: e.inv.Coverage.ArchivesSeen + progress.Archives,
		ArchiveEntries: e.inv.Coverage.ArchiveEntries + progress.Entries}, false)
}

type scanProgressReader struct {
	reader io.Reader
	emit   func()
}

func (r scanProgressReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	if n > 0 && r.emit != nil {
		r.emit()
	}
	return n, err
}

func NewScanner(cfg Config) *Scanner {
	threats, threatErr := LoadEmbeddedThreatBundle()
	return &Scanner{Config: cfg, Rules: RuleEngine{MaxFindings: cfg.Limits.MaxFindings, Threats: threats, ThreatError: threatErr}}
}

func (s *Scanner) ScanDirectory(root, phase string) (*Inventory, error) {
	return s.ScanDirectoryWithProgress(root, phase, nil)
}

func (s *Scanner) ScanDirectoryWithProgress(root, phase string, progress scanProgressFunc) (*Inventory, error) {
	return s.scanDirectoryWithProgress(root, phase, progress, scanOptions{})
}

func (s *Scanner) bindDirectory(root, phase string) (*Inventory, error) {
	return s.scanDirectoryWithProgress(root, phase, nil, scanOptions{bindingOnly: true})
}

func (s *Scanner) scanDirectoryWithProgress(root, phase string, progress scanProgressFunc, options scanOptions) (*Inventory, error) {
	if phase != "pre" && phase != "post" {
		return nil, fmt.Errorf("unsupported directory phase: %s", phase)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(resolved, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open scan root: %w", err)
	}
	defer unix.Close(fd)
	inv := &Inventory{Root: resolved, Phase: phase, Coverage: Coverage{Complete: true, Notes: []string{}}, started: time.Now(), Verification: SourceVerification{Checksums: "unknown", PGP: "unknown"}, vendorPaths: map[string]bool{}}
	emitter := &scannerProgressEmitter{inv: inv, callback: progress}
	emitter.emit(ScanOperationInventory, true)
	inv.active = readActiveControlPaths(fd, s.Config.Limits.MaxTextPerFile)
	if raw, ok := readSmallRegularAt(fd, ".SRCINFO", s.Config.Limits.MaxTextPerFile); ok {
		inv.Sources = parseSourceProvenance(raw, s.Config.Vendor.ScanDepth)
		for _, source := range inv.Sources {
			inv.vendorPaths[source.Name] = true
		}
		if !options.bindingOnly {
			inv.Findings = append(inv.Findings, sourceProvenanceFindings(inv.Sources)...)
		}
	}
	if err := s.walk(fd, "", inv, true, false, 0, options, emitter); err != nil {
		return nil, err
	}
	if phase == "pre" {
		emitter.emit(ScanOperationFinalizing, true)
		if !options.bindingOnly {
			s.compareSRCINFO(inv)
		}
	} else if !options.bindingOnly {
		if err := s.verifyExtractableSources(fd, inv, emitter); err != nil {
			return nil, err
		}
	}
	emitter.emit(ScanOperationFinalizing, true)
	s.finalize(inv)
	emitter.emit(ScanOperationComplete, true)
	return inv, nil
}

func (s *Scanner) ScanArtifacts(packages []string) (*Inventory, error) {
	return s.ScanArtifactsWithProgress(packages, nil)
}

func (s *Scanner) ScanArtifactsWithProgress(packages []string, progress scanProgressFunc) (*Inventory, error) {
	inv := &Inventory{Root: "<artifacts>", Phase: "artifact", Coverage: Coverage{Complete: true, Notes: []string{}}, started: time.Now(), Verification: SourceVerification{Checksums: "unknown", PGP: "not-applicable"}}
	emitter := &scannerProgressEmitter{inv: inv, callback: progress}
	emitter.emit(ScanOperationInventory, true)
	sort.Strings(packages)
	for _, requested := range packages {
		absolute, err := filepath.Abs(requested)
		if err != nil {
			return nil, err
		}
		parent := filepath.Dir(absolute)
		resolvedParent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return nil, err
		}
		if filepath.Clean(parent) != resolvedParent {
			return nil, fmt.Errorf("artifact parent contains a symlink: %s", parent)
		}
		fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		err = s.readRegular(fd, filepath.Base(absolute), filepath.Base(absolute), inv, false, 0, scanOptions{}, emitter)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
	}
	emitter.emit(ScanOperationFinalizing, true)
	s.finalize(inv)
	emitter.emit(ScanOperationComplete, true)
	return inv, nil
}

func (s *Scanner) walk(dirFD int, relative string, inv *Inventory, top, vendor bool, vendorBaseDepth int, options scanOptions, emitter *scannerProgressEmitter) error {
	if err := s.checkBudget(inv); err != nil {
		return err
	}
	dup, err := unix.Dup(dirFD)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(dup), "directory")
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return fmt.Errorf("enumerate %s: %w", displayPath(relative), err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if err := s.checkBudget(inv); err != nil {
			return err
		}
		name := entry.Name()
		rel := name
		if relative != "" {
			rel = relative + "/" + name
		}
		display := displayPath(rel)
		legacyMarker := top && (name == markerPrefix+"pre.json" || name == markerPrefix+"post.json")
		if legacyMarker {
			inv.Exclusions = append(inv.Exclusions, display)
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("stat %s: %w", display, err)
		}
		kind := st.Mode & unix.S_IFMT
		if top && inv.Phase == "pre" && inv.vendorPaths[name] && (kind == unix.S_IFREG || kind == unix.S_IFDIR) {
			suffix := ""
			if kind == unix.S_IFDIR {
				suffix = "/"
			}
			inv.Exclusions = append(inv.Exclusions, display+suffix)
			continue
		}
		excludedTop := name == ".git" || name == "pkg" || (inv.Phase == "pre" && name == "src")
		if kind == unix.S_IFDIR && (name == ".git" || (top && excludedTop)) {
			inv.Exclusions = append(inv.Exclusions, display+"/")
			continue
		}
		switch kind {
		case unix.S_IFDIR:
			childVendor, childDepth := vendor, vendorBaseDepth
			if top && inv.Phase == "post" && (name == "src" || inv.vendorPaths[name]) {
				childVendor, childDepth = true, 1
			}
			child, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return fmt.Errorf("open directory %s: %w", display, err)
			}
			err = s.walk(child, rel, inv, false, childVendor, childDepth, options, emitter)
			unix.Close(child)
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			fileVendor, fileDepth := vendor, vendorBaseDepth
			if top && inv.Phase == "post" && inv.vendorPaths[name] {
				fileVendor, fileDepth = true, 0
			}
			if err := s.readRegular(dirFD, name, rel, inv, fileVendor, fileDepth, options, emitter); err != nil {
				return err
			}
		case unix.S_IFLNK:
			if err := s.recordSymlink(dirFD, name, rel, st, inv, s.contentInspectionEnabled(vendor, vendorBaseDepth, options)); err != nil {
				return err
			}
		default:
			inv.Coverage.FilesSeen++
			inv.Files = append(inv.Files, FileRecord{Path: display, PathB64: pathB64(rel), Kind: fileKind(kind), Mode: st.Mode & 0o7777, Size: st.Size, BinaryMetadata: map[string]any{}})
			inv.Findings = append(inv.Findings, Finding{Severity: "critical", Category: "filesystem", File: display, Evidence: fileKind(kind), Rationale: "special files are not safe package inputs", RuleID: "special-file", HardBlock: true})
			inv.Coverage.Complete = false
		}
		if err := s.checkBudget(inv); err != nil {
			return err
		}
		emitter.emit(ScanOperationInventory, false)
	}
	return nil
}

func (s *Scanner) readRegular(dirFD int, name, rel string, inv *Inventory, vendor bool, vendorBaseDepth int, options scanOptions, emitter *scannerProgressEmitter) error {
	display := displayPath(rel)
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("safely open %s: %w", display, err)
	}
	file := os.NewFile(uintptr(fd), display)
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("file changed type while opening: %s", display)
	}
	if before.Size < 0 || inv.Coverage.BytesSeen > s.Config.Limits.MaxTotalInputBytes-before.Size {
		return fmt.Errorf("aggregate scanner input limit exceeded while opening %s", display)
	}
	first := make([]byte, 8192)
	tracked := scanProgressReader{reader: file, emit: func() { emitter.emit(ScanOperationInventory, false) }}
	n, readErr := io.ReadFull(tracked, first)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return readErr
	}
	first = first[:n]
	h := sha256.New()
	_, _ = h.Write(first)
	executable := before.Mode&0o111 != 0
	important := mandatoryControlPath(display) || inv.active[rel]
	isText := probablyText(first)
	contentInspection := s.contentInspectionEnabled(vendor, vendorBaseDepth, options)
	findings := []Finding{}
	sample := append([]byte(nil), first...)
	binaryCapture := append([]byte(nil), first...)
	total := int64(len(first))
	if !contentInspection {
		buffer := make([]byte, 1024*1024)
		for {
			n, readErr := tracked.Read(buffer)
			if n > 0 {
				_, _ = h.Write(buffer[:n])
				total += int64(n)
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		sample = nil
	} else if isText {
		validator := &contentValidator{}
		remaining := io.TeeReader(tracked, h)
		findings, sample, total, err = s.Rules.ScanReader(display, io.TeeReader(io.MultiReader(bytes.NewReader(first), remaining), validator), s.Config.Limits.MaxTextPerFile)
		if err != nil {
			return err
		}
		validator.Finish()
		if validator.NUL || validator.Invalid {
			if important || executable {
				reason := "mandatory control content is not valid UTF-8 text"
				if validator.NUL {
					reason = "mandatory control content contains an embedded NUL byte"
				}
				findings = append(findings, Finding{Severity: "critical", Category: "coverage", File: display,
					Evidence: "content classification", Rationale: reason, RuleID: "mandatory-control-invalid", HardBlock: true})
				inv.Coverage.Complete = false
			} else {
				isText = false
				binaryCapture = append(binaryCapture[:0], sample...)
			}
		}
		if isText {
			findings = append(findings, s.Rules.ScanSemantic(display, validUTF8OrReplacement(sample), executable, important)...)
		}
	} else {
		buffer := make([]byte, 1024*1024)
		for {
			n, err := tracked.Read(buffer)
			if n > 0 {
				_, _ = h.Write(buffer[:n])
				total += int64(n)
				if int64(len(binaryCapture)) < s.Config.Limits.BinaryStringsBytes {
					take := int(s.Config.Limits.BinaryStringsBytes - int64(len(binaryCapture)))
					if take > n {
						take = n
					}
					binaryCapture = append(binaryCapture, buffer[:take]...)
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return err
	}
	if !sameStat(before, after) || total != after.Size {
		return fmt.Errorf("TOCTOU change detected while reading %s", display)
	}
	selectedText, selectedReason := "", ""
	if contentInspection && isText && (executable || important || len(findings) > 0) {
		selectedText = validUTF8OrReplacement(sample)
		if important || len(findings) > 0 {
			selectedReason = "mandatory"
		} else {
			selectedReason = "executable"
		}
		if before.Size > s.Config.Limits.MaxTextPerFile {
			inv.Coverage.Complete = false
			inv.Coverage.Notes = append(inv.Coverage.Notes, "selected file exceeds text limit: "+display)
			findings = append(findings, Finding{Severity: "high", Category: "coverage", File: display, Evidence: fmt.Sprint(before.Size), Rationale: "selected text file exceeds configured review limit", RuleID: "selected-file-limit"})
		}
	}
	metadata := map[string]any{}
	if contentInspection && !isText {
		inv.Coverage.BinaryFiles++
		inv.Coverage.BinaryBytes += before.Size
		stringsText := printableStrings(binaryCapture)
		if !LooksLikeArchive(display, binaryCapture) {
			findings = append(findings, binaryStringFindings(s.Rules.ScanText(display, stringsText, 0))...)
		}
		var metadataFinding *Finding
		metadata, metadataFinding = binaryMetadata(display, binaryCapture, before.Size)
		if metadataFinding != nil {
			findings = append(findings, *metadataFinding)
		}
		if inv.Phase == "pre" && metadata["format"] != nil {
			findings = append(findings, Finding{Severity: "high", Category: "integrity", File: display,
				Evidence: fmt.Sprint(metadata["format"]), Rationale: "the submitted AUR repository contains a native executable binary that cannot be meaningfully reviewed from source",
				RuleID: "repository-native-binary"})
		}
		if (important || executable) && (important || len(metadata) == 0) {
			findings = append(findings, Finding{Severity: "critical", Category: "coverage", File: display,
				Evidence: "unknown or binary control format", Rationale: "mandatory executable or control content is not fully inspectable text",
				RuleID: "mandatory-control-invalid", HardBlock: true})
			inv.Coverage.Complete = false
		}
		if executable || len(findings) > 0 || len(metadata) > 0 {
			selectedText = binaryReviewText(metadata, stringsText)
			selectedReason = "binary-metadata"
		}
	}
	record := FileRecord{Path: display, PathB64: pathB64(rel), Kind: "file", Mode: before.Mode & 0o7777, Size: before.Size, SHA256: hex.EncodeToString(h.Sum(nil)), Executable: executable, Text: isText, SelectedText: selectedText, SelectedReason: selectedReason, BinaryMetadata: metadata}
	inv.Files = append(inv.Files, record)
	recordIndex := len(inv.Files) - 1
	inv.Coverage.FilesSeen++
	inv.Coverage.BytesSeen += before.Size
	inv.Findings = append(inv.Findings, findings...)
	if isText {
		inv.Coverage.TextFiles++
		inv.Coverage.TextBytes += before.Size
	}
	looksArchive := LooksLikeArchive(display, first)
	if looksArchive {
		inv.Files[recordIndex].ArchiveFormat = archiveFormat(first)
	}
	archiveInspection := !options.bindingOnly && looksArchive && (!vendor || s.Config.Vendor.ScanDepth > vendorBaseDepth)
	if archiveInspection {
		if inv.Coverage.ArchivesSeen >= s.Config.Limits.MaxArchives {
			return fmt.Errorf("aggregate archive count limit exceeded at %s", display)
		}
		dup, err := unix.Dup(fd)
		if err != nil {
			return err
		}
		archiveFile := os.NewFile(uintptr(dup), display)
		if _, err = archiveFile.Seek(0, io.SeekStart); err != nil {
			archiveFile.Close()
			return err
		}
		archiveConfig := s.Config
		archiveConfig.Limits.MaxArchiveEntries -= inv.Coverage.ArchiveEntries
		archiveConfig.Limits.MaxArchiveUnpackedBytes -= inv.Coverage.ArchiveUnpackedBytes
		archiveConfig.Limits.MaxArchives -= inv.Coverage.ArchivesSeen
		policyDepth := -1
		startDepth := 0
		if vendor {
			policyDepth = s.Config.Vendor.ScanDepth
			startDepth = vendorBaseDepth
		}
		archiveResult := scanArchiveWithPolicyDepth(archiveFile, display, archiveConfig, s.Rules, startDepth, policyDepth, emitter.emitArchive)
		archiveFile.Close()
		inv.Files[recordIndex].ArchiveEntries = archiveResult.Entries
		inv.Files[recordIndex].ArchiveFormat = archiveResult.Format
		inv.Coverage.ArchivesSeen += archiveResult.Archives
		inv.Coverage.ArchiveEntries += archiveResult.Entries
		inv.Coverage.ArchiveUnpackedBytes += archiveResult.UnpackedBytes
		inv.Findings = append(inv.Findings, archiveResult.Findings...)
		if !archiveResult.Supported || !archiveResult.Complete {
			inv.Coverage.Complete = false
			inv.Coverage.Notes = append(inv.Coverage.Notes, "unsupported archive: "+display)
		}
		for _, selected := range archiveResult.Selected {
			encoded := []byte(selected.Text)
			inv.Files = append(inv.Files, FileRecord{Path: selected.Path, PathB64: base64.URLEncoding.EncodeToString([]byte(selected.Path)), Kind: "archive-member", Size: int64(len(encoded)), SHA256: SHA256Bytes(encoded), Text: true, SelectedText: selected.Text, SelectedReason: "archive-member", BinaryMetadata: map[string]any{}})
		}
	}
	emitter.emit(ScanOperationInventory, false)
	return s.checkBudget(inv)
}

func (s *Scanner) verifyExtractableSources(rootFD int, inv *Inventory, emitter *scannerProgressEmitter) error {
	emitter.emit(ScanOperationSourceVerification, true)
	indices := make(map[string]int, len(inv.Files))
	var srcinfo *FileRecord
	for index := range inv.Files {
		record := &inv.Files[index]
		indices[record.Path] = index
		if record.Path == ".SRCINFO" && record.Kind == "file" {
			srcinfo = record
		}
	}
	if srcinfo == nil || srcinfo.SelectedText == "" {
		inv.Coverage.Complete = false
		inv.Findings = append(inv.Findings, Finding{Severity: "high", Category: "coverage", File: ".SRCINFO",
			Evidence: "missing or unreadable", Rationale: "post-download archive probing requires complete .SRCINFO metadata",
			RuleID: "srcinfo-missing", HardBlock: true})
		return nil
	}
	for name := range parseExtractableSources([]byte(srcinfo.SelectedText), s.Config.Limits.MaxTextPerFile) {
		if err := s.checkBudget(inv); err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Fstatat(rootFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			inv.Coverage.Complete = false
			inv.Findings = append(inv.Findings, Finding{Severity: "high", Category: "coverage", File: name,
				Evidence: "extractable source is absent", Rationale: "a source makepkg may extract is missing from the completed inventory",
				RuleID: "extractable-source-missing", HardBlock: true})
			continue
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			continue // VCS sources are checked recursively by the directory walk.
		}
		index, ok := indices[name]
		if !ok || inv.Files[index].Kind != "file" || st.Mode&unix.S_IFMT != unix.S_IFREG {
			inv.Coverage.Complete = false
			inv.Findings = append(inv.Findings, Finding{Severity: "critical", Category: "coverage", File: name,
				Evidence: "non-regular extractable source", Rationale: "makepkg source extraction is permitted only for inventoried regular files",
				RuleID: "extractable-source-invalid", HardBlock: true})
			continue
		}
		if inv.vendorPaths[name] && s.Config.Vendor.ScanDepth == 0 {
			inv.Files[index].Extractable = inv.Files[index].ArchiveFormat != "" || archiveFormatFromName(name) != ""
			emitter.emit(ScanOperationSourceVerification, false)
			continue
		}
		fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("reopen extractable source %s: %w", name, err)
		}
		file := os.NewFile(uintptr(fd), name)
		var before, after unix.Stat_t
		hash := sha256.New()
		if err = unix.Fstat(fd, &before); err == nil {
			tracked := scanProgressReader{reader: file, emit: func() { emitter.emit(ScanOperationSourceVerification, false) }}
			_, err = io.Copy(hash, tracked)
		}
		if err == nil {
			err = unix.Fstat(fd, &after)
		}
		if err == nil && (!sameStat(before, after) || before.Mode&unix.S_IFMT != unix.S_IFREG ||
			before.Size != inv.Files[index].Size || hex.EncodeToString(hash.Sum(nil)) != inv.Files[index].SHA256) {
			err = errors.New("source changed after inventory scan")
		}
		if err == nil {
			_, err = file.Seek(0, io.SeekStart)
		}
		var recognized bool
		if err == nil {
			recognized, err = makepkgArchiveProber(fd)
		}
		file.Close()
		if err != nil {
			return fmt.Errorf("verify extractable source %s: %w", name, err)
		}
		inv.Files[index].Extractable = recognized
		if recognized && inv.Files[index].ArchiveFormat == "" {
			inv.Coverage.Complete = false
			inv.Findings = append(inv.Findings, Finding{Severity: "critical", Category: "coverage", File: name,
				Evidence: "bsdtar recognizes source", Rationale: "makepkg would extract a source the in-process scanner cannot recognize",
				RuleID: "makepkg-archive-unsupported", HardBlock: true})
		}
		emitter.emit(ScanOperationSourceVerification, false)
	}
	return s.checkBudget(inv)
}

func (s *Scanner) contentInspectionEnabled(vendor bool, vendorBaseDepth int, options scanOptions) bool {
	return !options.bindingOnly && (!vendor || s.Config.Vendor.ScanDepth >= max(1, vendorBaseDepth))
}

func (s *Scanner) recordSymlink(dirFD int, name, rel string, before unix.Stat_t, inv *Inventory, inspect bool) error {
	buffer := make([]byte, 4097)
	n, err := unix.Readlinkat(dirFD, name, buffer)
	if err != nil {
		return err
	}
	if n > 4096 {
		return errors.New("symlink target exceeds limit")
	}
	target := string(buffer[:n])
	var after unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameLinkStat(before, after) {
		return fmt.Errorf("TOCTOU change detected while reading symlink %s", displayPath(rel))
	}
	display := displayPath(rel)
	inv.Files = append(inv.Files, FileRecord{Path: display, PathB64: pathB64(rel), Kind: "symlink", Mode: before.Mode & 0o7777, Size: before.Size, LinkTarget: target, BinaryMetadata: map[string]any{}})
	inv.Coverage.FilesSeen++
	clean := path.Clean(path.Join(path.Dir(display), target))
	if inspect && (strings.HasPrefix(target, "/") || clean == ".." || strings.HasPrefix(clean, "../")) {
		inv.Findings = append(inv.Findings, Finding{Severity: "critical", Category: "filesystem", File: display, Evidence: truncate(target, 320), Rationale: "symlink escapes the package tree", RuleID: "symlink-escape", HardBlock: true})
	}
	return nil
}

func sameLinkStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Size == b.Size && a.Mtim == b.Mtim
}

var scalarAssignmentRE = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$`)
var srcFieldRE = regexp.MustCompile(`^\s*(pkgbase|pkgver|pkgrel|epoch|pkgdesc|url)\s*=\s*(.*?)\s*$`)
var sourceFieldRE = regexp.MustCompile(`^\s*(source(?:_[A-Za-z0-9_]+)?|install)\s*=\s*(.*?)\s*$`)
var remoteSourceRE = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9+.-]*://|(?:git|svn|hg|bzr)\+)`)

func (s *Scanner) compareSRCINFO(inv *Inventory) {
	byPath := map[string]FileRecord{}
	for _, item := range inv.Files {
		byPath[item.Path] = item
	}
	pkg, pkgOK := byPath["PKGBUILD"]
	src, srcOK := byPath[".SRCINFO"]
	if !pkgOK || !srcOK || pkg.SelectedText == "" || src.SelectedText == "" {
		inv.Findings = append(inv.Findings, Finding{Severity: "high", Category: "coverage", File: ".SRCINFO", Evidence: "missing or unreadable", Rationale: "PKGBUILD and .SRCINFO are both required", RuleID: "srcinfo-missing"})
		inv.Coverage.Complete = false
		return
	}
	pkgFields := staticPKGBUILDScalars(pkg.SelectedText)
	srcFields := map[string]string{}
	for _, line := range strings.Split(src.SelectedText, "\n") {
		if match := srcFieldRE.FindStringSubmatch(line); match != nil {
			if _, ok := srcFields[match[1]]; !ok {
				srcFields[match[1]] = match[2]
			}
		}
	}
	for key, value := range pkgFields {
		if other, ok := srcFields[key]; ok && other != value {
			inv.Findings = append(inv.Findings, Finding{Severity: "high", Category: "package_metadata", File: ".SRCINFO", Evidence: fmt.Sprintf("%s: %q != %q", key, other, value), Rationale: "static PKGBUILD metadata differs from .SRCINFO", RuleID: "srcinfo-mismatch"})
		}
	}
	known := map[string]bool{}
	for _, item := range inv.Files {
		if item.Kind == "file" || item.Kind == "symlink" {
			known[item.Path] = true
		}
	}
	for index, line := range strings.Split(src.SelectedText, "\n") {
		match := sourceFieldRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		value := match[2]
		source := value
		if pieces := strings.SplitN(value, "::", 2); len(pieces) == 2 {
			source = pieces[1]
		}
		if strings.HasPrefix(match[1], "source") && remoteSourceRE.MatchString(source) {
			continue
		}
		clean := path.Clean(source)
		ln := index + 1
		if strings.HasPrefix(source, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
			inv.Findings = append(inv.Findings, Finding{Severity: "critical", Category: "filesystem", File: ".SRCINFO", Line: &ln, Evidence: truncate(value, 320), Rationale: "local source reference escapes the package tree", RuleID: "source-reference-escape", HardBlock: true})
		} else if !known[clean] {
			inv.Findings = append(inv.Findings, Finding{Severity: "high", Category: "coverage", File: ".SRCINFO", Line: &ln, Evidence: truncate(value, 320), Rationale: "referenced local source or install file is missing from the inventory", RuleID: "source-reference-missing"})
		}
	}
}

// staticPKGBUILDScalars resolves only assignment syntax whose value can be
// determined without executing Bash. Variable names are discovered from the
// package itself; unsupported shell syntax simply makes that assignment
// unavailable to the best-effort .SRCINFO comparison.
func staticPKGBUILDScalars(text string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if len(values) >= 1024 {
			break
		}
		match := scalarAssignmentRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		value, ok := evaluateStaticShellScalar(match[2], values)
		if ok && len(value) <= 8192 {
			values[match[1]] = value
		}
	}
	return values
}

func evaluateStaticShellScalar(input string, variables map[string]string) (string, bool) {
	var output strings.Builder
	quote := byte(0)
	for index := 0; index < len(input); {
		character := input[index]
		if quote == '\'' {
			if character == '\'' {
				quote = 0
			} else {
				output.WriteByte(character)
			}
			index++
			continue
		}
		if character == '\'' {
			quote = '\''
			index++
			continue
		}
		if character == '"' {
			if quote == '"' {
				quote = 0
			} else if quote == 0 {
				quote = '"'
			} else {
				return "", false
			}
			index++
			continue
		}
		if character == '`' {
			return "", false
		}
		if character == '\\' {
			if index+1 >= len(input) {
				return "", false
			}
			next := input[index+1]
			if quote == '"' && next != '$' && next != '"' && next != '\\' && next != '`' {
				output.WriteByte(character)
			} else {
				output.WriteByte(next)
				index++
			}
			index++
			continue
		}
		if character == '$' {
			name, consumed, ok := staticVariableReference(input[index:])
			if !ok {
				return "", false
			}
			value, known := variables[name]
			if !known {
				return "", false
			}
			output.WriteString(value)
			if output.Len() > 8192 {
				return "", false
			}
			index += consumed
			continue
		}
		if quote == 0 {
			if character == '#' && (index == 0 || input[index-1] == ' ' || input[index-1] == '\t') {
				break
			}
			if character == ' ' || character == '\t' {
				for index < len(input) && (input[index] == ' ' || input[index] == '\t') {
					index++
				}
				if index == len(input) || input[index] == '#' {
					break
				}
				return "", false
			}
			if strings.ContainsRune("();&|<>", rune(character)) {
				return "", false
			}
		}
		output.WriteByte(character)
		if output.Len() > 8192 {
			return "", false
		}
		index++
	}
	return output.String(), quote == 0
}

func staticVariableReference(input string) (string, int, bool) {
	if len(input) < 2 || input[0] != '$' {
		return "", 0, false
	}
	if input[1] == '{' {
		end := strings.IndexByte(input[2:], '}')
		if end < 0 {
			return "", 0, false
		}
		name := input[2 : end+2]
		if !shellIdentifier(name) {
			return "", 0, false
		}
		return name, end + 3, true
	}
	end := 1
	for end < len(input) && (input[end] == '_' || input[end] >= 'A' && input[end] <= 'Z' || input[end] >= 'a' && input[end] <= 'z' || end > 1 && input[end] >= '0' && input[end] <= '9') {
		end++
	}
	name := input[1:end]
	return name, end, shellIdentifier(name)
}

func shellIdentifier(value string) bool {
	if value == "" || !(value[0] == '_' || value[0] >= 'A' && value[0] <= 'Z' || value[0] >= 'a' && value[0] <= 'z') {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character != '_' && !(character >= 'A' && character <= 'Z') && !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func (s *Scanner) finalize(inv *Inventory) {
	indices := []int{}
	for i := range inv.Files {
		if inv.Files[i].SelectedText != "" {
			if s.Config.Review.Mode == ReviewModeDeterministicOnly {
				inv.Files[i].SelectedText = ""
				continue
			}
			indices = append(indices, i)
			inv.Coverage.ReviewEligibleFiles++
			inv.Coverage.ReviewEligibleBytes += int64(len([]byte(inv.Files[i].SelectedText)))
		}
	}
	sort.Slice(indices, func(i, j int) bool {
		a, b := inv.Files[indices[i]], inv.Files[indices[j]]
		pa, pb := selectionPriority(a.SelectedReason), selectionPriority(b.SelectedReason)
		if pa != pb {
			return pa < pb
		}
		return a.PathB64 < b.PathB64
	})
	var used int64
	for _, index := range indices {
		record := &inv.Files[index]
		size := int64(len([]byte(record.SelectedText)))
		mandatory := record.SelectedReason == "mandatory" || record.SelectedReason == "archive-member" || len(record.BinaryMetadata) > 0
		if used+size <= s.Config.Limits.MaxSelectedTextBytes {
			used += size
			continue
		}
		record.SelectedText = ""
		inv.Coverage.OmittedReviewFiles++
		inv.Coverage.OmittedReviewBytes += size
		if mandatory {
			inv.Coverage.Complete = false
			inv.Coverage.Notes = append(inv.Coverage.Notes, "mandatory AI selection exceeds aggregate limit: "+record.Path)
			inv.Findings = append(inv.Findings, Finding{Severity: "high", Category: "coverage", File: record.Path, Evidence: fmt.Sprint(size), Rationale: "mandatory review text exceeds aggregate AI limit", RuleID: "aggregate-selection-limit"})
		}
	}
	inv.Coverage.SelectedBytes = used
	for _, index := range indices {
		if inv.Files[index].SelectedText != "" {
			inv.Coverage.SelectedFiles++
		}
	}
	for _, finding := range inv.Findings {
		if finding.Category == "coverage" {
			inv.Coverage.Complete = false
		}
	}
	for index := range inv.Findings {
		inv.Findings[index].Source = "deterministic"
	}
	sortFindings(inv.Findings)
	sort.Strings(inv.Exclusions)
	sort.Slice(inv.Files, func(i, j int) bool { return inv.Files[i].PathB64 < inv.Files[j].PathB64 })
	bindObservedSources(inv)
	manifest := make([]map[string]any, len(inv.Files))
	for i, item := range inv.Files {
		manifest[i] = item.ManifestValue()
	}
	raw, _ := CanonicalJSON(manifest)
	inv.ManifestHash = SHA256Bytes(raw)
}

func (s *Scanner) checkBudget(inv *Inventory) error {
	if !inv.started.IsZero() && time.Since(inv.started) > time.Duration(s.Config.Limits.ScanTimeoutSeconds)*time.Second {
		return ErrScannerTimeout
	}
	if inv.Coverage.FilesSeen > s.Config.Limits.MaxFiles {
		return errors.New("aggregate scanner file limit exceeded")
	}
	if inv.Coverage.BytesSeen > s.Config.Limits.MaxTotalInputBytes {
		return errors.New("aggregate scanner byte limit exceeded")
	}
	if len(inv.Findings) > s.Config.Limits.MaxFindings {
		return errors.New("aggregate scanner finding limit exceeded")
	}
	if inv.Coverage.ArchivesSeen > s.Config.Limits.MaxArchives || inv.Coverage.ArchiveEntries > s.Config.Limits.MaxArchiveEntries || inv.Coverage.ArchiveUnpackedBytes > s.Config.Limits.MaxArchiveUnpackedBytes {
		return errors.New("aggregate scanner archive limit exceeded")
	}
	return nil
}

func pathB64(value string) string { return base64.URLEncoding.EncodeToString([]byte(value)) }
func displayPath(value string) string {
	if value == "" {
		return "."
	}
	var out strings.Builder
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&out, "\\x%02x", value[0])
			value = value[1:]
			continue
		}
		out.WriteRune(r)
		value = value[size:]
	}
	return out.String()
}
func fileKind(kind uint32) string {
	switch kind {
	case unix.S_IFIFO:
		return "fifo"
	case unix.S_IFCHR:
		return "char-device"
	case unix.S_IFBLK:
		return "block-device"
	case unix.S_IFSOCK:
		return "socket"
	default:
		return "special"
	}
}
func selectionPriority(value string) int {
	switch value {
	case "mandatory":
		return 0
	case "archive-member":
		return 1
	case "binary-metadata":
		return 2
	case "executable":
		return 3
	default:
		return 4
	}
}

func binaryMetadata(file string, data []byte, fullSize int64) (map[string]any, *Finding) {
	bad := func(err error) (map[string]any, *Finding) {
		finding := Finding{Severity: "high", Category: "coverage", File: file, Evidence: err.Error(), Rationale: "executable binary header could not be safely parsed", RuleID: "binary-header-invalid"}
		return map[string]any{}, &finding
	}
	if bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) {
		if len(data) < 20 || (data[4] != 1 && data[4] != 2) || (data[5] != 1 && data[5] != 2) {
			return bad(errors.New("invalid ELF identification"))
		}
		var order binary.ByteOrder = binary.LittleEndian
		if data[5] == 2 {
			order = binary.BigEndian
		}
		return map[string]any{"format": "ELF", "class_bits": map[byte]int{1: 32, 2: 64}[data[4]], "machine": order.Uint16(data[18:20]), "size": fullSize}, nil
	}
	if bytes.HasPrefix(data, []byte("MZ")) {
		if len(data) < 64 {
			return bad(errors.New("truncated DOS header"))
		}
		offset := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
		if offset+24 > len(data) || !bytes.Equal(data[offset:offset+4], []byte{'P', 'E', 0, 0}) {
			return bad(errors.New("invalid PE header offset"))
		}
		return map[string]any{"format": "PE", "machine": binary.LittleEndian.Uint16(data[offset+4 : offset+6]), "sections": binary.LittleEndian.Uint16(data[offset+6 : offset+8]), "size": fullSize}, nil
	}
	if len(data) >= 4 {
		magic := binary.BigEndian.Uint32(data[:4])
		orders := map[uint32]struct {
			order binary.ByteOrder
			bits  int
		}{0xfeedface: {binary.BigEndian, 32}, 0xcefaedfe: {binary.LittleEndian, 32}, 0xfeedfacf: {binary.BigEndian, 64}, 0xcffaedfe: {binary.LittleEndian, 64}}
		if spec, ok := orders[magic]; ok {
			minimum := 28
			if spec.bits == 64 {
				minimum = 32
			}
			if len(data) < minimum {
				return bad(errors.New("truncated Mach-O header"))
			}
			return map[string]any{"format": "Mach-O", "class_bits": spec.bits, "cpu_type": spec.order.Uint32(data[4:8]), "file_type": spec.order.Uint32(data[12:16]), "commands": spec.order.Uint32(data[16:20]), "size": fullSize}, nil
		}
	}
	return map[string]any{}, nil
}
func binaryReviewText(metadata map[string]any, stringsText string) string {
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pieces := make([]string, 0, len(keys))
	for _, key := range keys {
		pieces = append(pieces, fmt.Sprintf("%s=%v", key, metadata[key]))
	}
	result := "Binary metadata: [" + strings.Join(pieces, ", ") + "]"
	if stringsText != "" {
		result += "\nBounded printable strings:\n" + stringsText
	}
	return result
}
