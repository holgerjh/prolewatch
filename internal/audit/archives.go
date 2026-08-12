package audit

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

var archiveSuffixes = []string{
	".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
	".tar.zst", ".zip", ".jar", ".whl", ".pkg.tar.zst", ".pkg.tar.xz",
}

type ArchiveScan struct {
	Entries       int
	UnpackedBytes int64
	Archives      int
	Findings      []Finding
	Selected      []SelectedContent
	Supported     bool
	Complete      bool
	Format        string
}

type ArchiveProgress struct {
	Archives int
	Entries  int
}

type archiveProgressFunc func(ArchiveProgress)

func emitArchiveProgress(result *ArchiveScan, progress archiveProgressFunc) {
	if result != nil && progress != nil {
		progress(ArchiveProgress{Archives: result.Archives, Entries: result.Entries})
	}
}

type archiveProgressReader struct {
	reader   io.Reader
	result   *ArchiveScan
	progress archiveProgressFunc
}

func (r archiveProgressReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	if n > 0 {
		emitArchiveProgress(r.result, r.progress)
	}
	return n, err
}

type SelectedContent struct{ Path, Text string }

func LooksLikeArchive(name string, head []byte) bool {
	lower := strings.ToLower(name)
	for _, suffix := range archiveSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return archiveFormat(head) != ""
}

func archiveFormat(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		return "zip"
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return "gzip"
	case bytes.HasPrefix(head, []byte("BZh")):
		return "bzip2"
	case bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z'}):
		return "xz"
	case bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return "zstd"
	case bytes.HasPrefix(head, []byte("070701")) || bytes.HasPrefix(head, []byte("070702")) || bytes.HasPrefix(head, []byte("070707")) ||
		bytes.HasPrefix(head, []byte{0xc7, 0x71}) || bytes.HasPrefix(head, []byte{0x71, 0xc7}):
		return "cpio"
	case len(head) >= 262 && bytes.Equal(head[257:262], []byte("ustar")):
		return "tar"
	default:
		return ""
	}
}

func unsafeArchiveMember(name string) bool {
	if name == "" || strings.ContainsRune(name, 0) || strings.HasPrefix(name, "/") {
		return true
	}
	clean := path.Clean(name)
	return clean == ".." || strings.HasPrefix(clean, "../")
}

func archiveLinkEscapes(member, target string) bool {
	if strings.HasPrefix(target, "/") || strings.ContainsRune(target, 0) {
		return true
	}
	clean := path.Clean(path.Join(path.Dir(member), target))
	return clean == ".." || strings.HasPrefix(clean, "../")
}

func archiveEscapeFinding(file, evidence, rationale string) Finding {
	return Finding{Severity: "critical", Category: "archive_escape", File: file, Evidence: truncate(evidence, 320), Rationale: rationale, RuleID: "archive-escape", HardBlock: true}
}

func ScanArchive(reader io.ReadSeeker, displayName string, cfg Config, rules RuleEngine, depth int) ArchiveScan {
	return scanArchiveWithPolicyDepth(reader, displayName, cfg, rules, depth, -1, nil)
}

func scanArchive(reader io.ReadSeeker, displayName string, cfg Config, rules RuleEngine, depth int, progress archiveProgressFunc) ArchiveScan {
	return scanArchiveWithPolicyDepth(reader, displayName, cfg, rules, depth, -1, progress)
}

func scanArchiveWithPolicyDepth(reader io.ReadSeeker, displayName string, cfg Config, rules RuleEngine, depth, policyDepth int, progress archiveProgressFunc) ArchiveScan {
	if rules.MaxFindings <= 0 || rules.MaxFindings > cfg.Limits.MaxFindings {
		rules.MaxFindings = cfg.Limits.MaxFindings
	}
	result := ArchiveScan{Supported: true, Complete: true, Archives: 1}
	emitArchiveProgress(&result, progress)
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return unsupportedArchive(result, displayName, err)
	}
	head := make([]byte, 512)
	n, err := io.ReadFull(reader, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return unsupportedArchive(result, displayName, err)
	}
	head = head[:n]
	result.Format = archiveFormat(head)
	if result.Format == "cpio" {
		return unsupportedArchive(result, displayName, errors.New("cpio is extractable by makepkg but has no in-process scanner"))
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return unsupportedArchive(result, displayName, err)
	}
	if result.Format == "zip" {
		at, ok := reader.(io.ReaderAt)
		if !ok {
			return unsupportedArchive(result, displayName, errors.New("zip input does not support random access"))
		}
		end, err := reader.Seek(0, io.SeekEnd)
		if err != nil {
			return unsupportedArchive(result, displayName, err)
		}
		if err := scanZip(at, end, displayName, cfg, rules, &result, depth, policyDepth, progress); err != nil {
			return unsupportedArchive(result, displayName, err)
		}
		return result
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return unsupportedArchive(result, displayName, err)
	}
	recognized, err := scanTar(reader, head, displayName, cfg, rules, &result, depth, policyDepth, progress)
	if err == nil && recognized {
		return result
	}
	if result.Format == "gzip" || result.Format == "bzip2" || result.Format == "xz" || result.Format == "zstd" {
		if _, seekErr := reader.Seek(0, io.SeekStart); seekErr != nil {
			return unsupportedArchive(result, displayName, seekErr)
		}
		result = ArchiveScan{Supported: true, Complete: true, Archives: 1, Format: archiveFormat(head)}
		if err := scanCompressedStream(reader, head, displayName, cfg, rules, &result, progress); err != nil {
			return unsupportedArchive(result, displayName, err)
		}
		return result
	}
	if err == nil {
		err = errors.New("unrecognized archive")
	}
	return unsupportedArchive(result, displayName, err)
}

func unsupportedArchive(result ArchiveScan, name string, err error) ArchiveScan {
	result.Supported = false
	result.Complete = false
	result.Findings = append(result.Findings, Finding{Severity: "high", Category: "coverage", File: name,
		Evidence: fmt.Sprintf("%T", err), Rationale: "archive could not be safely inspected", RuleID: "archive-unsupported"})
	return result
}

func compressedReader(source io.Reader, head []byte) (io.Reader, io.Closer, error) {
	buffered := bufio.NewReader(source)
	switch {
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		r, err := gzip.NewReader(buffered)
		return r, r, err
	case bytes.HasPrefix(head, []byte("BZh")):
		return bzip2.NewReader(buffered), nil, nil
	case bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z'}):
		r, err := xz.NewReader(buffered)
		return r, nil, err
	case bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		r, err := zstd.NewReader(buffered)
		return r, r.IOReadCloser(), err
	default:
		return buffered, nil, nil
	}
}

func scanTar(source io.Reader, head []byte, display string, cfg Config, rules RuleEngine, result *ArchiveScan, depth, policyDepth int, progress archiveProgressFunc) (bool, error) {
	decompressed, closer, err := compressedReader(source, head)
	if err != nil {
		return false, err
	}
	if closer != nil {
		defer closer.Close()
	}
	tr := tar.NewReader(decompressed)
	recognized := false
	ownerReported := false
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return recognized, nil
		}
		if err != nil {
			return recognized, err
		}
		recognized = true
		virtual := display + "!/" + header.Name
		if !checkArchiveLimits(result, header.Size, cfg, virtual) {
			emitArchiveProgress(result, progress)
			return true, nil
		}
		emitArchiveProgress(result, progress)
		if unsafeArchiveMember(header.Name) {
			result.Findings = append(result.Findings, archiveEscapeFinding(virtual, header.Name, "archive member escapes its extraction root"))
			continue
		}
		switch header.Typeflag {
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			result.Findings = append(result.Findings, archiveEscapeFinding(virtual, header.Name, "archive contains a device or FIFO"))
			continue
		case tar.TypeSymlink:
			if archiveLinkEscapes(header.Name, header.Linkname) {
				result.Findings = append(result.Findings, archiveEscapeFinding(virtual, header.Linkname, "archive link escapes its extraction root"))
			}
			continue
		case tar.TypeLink:
			if unsafeArchiveMember(header.Linkname) {
				result.Findings = append(result.Findings, archiveEscapeFinding(virtual, header.Linkname, "archive link escapes its extraction root"))
			}
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			continue
		}
		if !ownerReported && packageArchiveName(display) && (header.Uid != 0 || header.Gid != 0) {
			result.Findings = append(result.Findings, Finding{Severity: "medium", Category: "package_metadata", File: virtual,
				Evidence: fmt.Sprintf("uid=%d gid=%d", header.Uid, header.Gid), Rationale: "package archive records non-root numeric ownership", RuleID: "archive-owner"})
			ownerReported = true
		}
		archiveModeFindings(header.Name, uint32(header.Mode), header.PAXRecords, virtual, result)
		if err := scanArchiveMember(io.LimitReader(tr, header.Size), header.Size, header.Name, virtual, uint32(header.Mode), cfg, rules, result, depth, policyDepth, progress); err != nil {
			return true, err
		}
		if err := checkArchiveBudget(result, cfg); err != nil {
			return true, err
		}
	}
}

func scanZip(at io.ReaderAt, size int64, display string, cfg Config, rules RuleEngine, result *ArchiveScan, depth, policyDepth int, progress archiveProgressFunc) error {
	zr, err := zip.NewReader(at, size)
	if err != nil {
		return err
	}
	for _, member := range zr.File {
		virtual := display + "!/" + member.Name
		declared := int64(member.UncompressedSize64)
		if !checkArchiveLimits(result, declared, cfg, virtual) {
			emitArchiveProgress(result, progress)
			return nil
		}
		emitArchiveProgress(result, progress)
		if member.Flags&1 != 0 {
			result.Findings = append(result.Findings, Finding{Severity: "high", Category: "coverage", File: virtual, Evidence: "encrypted", Rationale: "encrypted archive member cannot be inspected", RuleID: "archive-encrypted"})
			continue
		}
		if unsafeArchiveMember(member.Name) {
			result.Findings = append(result.Findings, archiveEscapeFinding(virtual, member.Name, "archive member escapes its extraction root"))
			continue
		}
		mode := member.Mode()
		if mode&0o6000 != 0 {
			result.Findings = append(result.Findings, Finding{Severity: "critical", Category: "privilege_escalation", File: virtual, Evidence: fmt.Sprintf("%#o", mode.Perm()), Rationale: "package artifact contains a setuid or setgid entry", RuleID: "artifact-setid", HardBlock: true})
		}
		if privilegedPackagePath(member.Name) {
			result.Findings = append(result.Findings, Finding{Severity: "medium", Category: "persistence", File: virtual, Evidence: member.Name, Rationale: "package artifact installs a privileged integration surface", RuleID: "artifact-integration"})
		}
		if mode&os.ModeSymlink != 0 {
			r, err := member.Open()
			if err != nil {
				return err
			}
			target, readErr := io.ReadAll(io.LimitReader(r, 4097))
			r.Close()
			if readErr != nil {
				return readErr
			}
			if len(target) > 4096 {
				return errors.New("oversized archive symlink")
			}
			if archiveLinkEscapes(member.Name, string(target)) {
				result.Findings = append(result.Findings, archiveEscapeFinding(virtual, string(target), "archive symlink escapes its extraction root"))
			}
			continue
		}
		if member.FileInfo().IsDir() {
			continue
		}
		if !mode.IsRegular() {
			result.Findings = append(result.Findings, archiveEscapeFinding(virtual, fmt.Sprintf("%#o", mode), "archive contains a special filesystem entry"))
			continue
		}
		r, err := member.Open()
		if err != nil {
			return err
		}
		if err := checkArchiveBudget(result, cfg); err != nil {
			return err
		}
		err = scanArchiveMember(r, declared, member.Name, virtual, uint32(mode.Perm()), cfg, rules, result, depth, policyDepth, progress)
		r.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func checkArchiveLimits(result *ArchiveScan, size int64, cfg Config, file string) bool {
	result.Entries++
	if size < 0 {
		result.Complete = false
		result.Findings = append(result.Findings, Finding{Severity: "high", Category: "coverage", File: file, Evidence: fmt.Sprint(size), Rationale: "archive member has an invalid negative or overflowing size", RuleID: "archive-size-invalid"})
		return false
	}
	if size > 0 {
		result.UnpackedBytes += size
	}
	if result.Entries > cfg.Limits.MaxArchiveEntries {
		result.Complete = false
		result.Findings = append(result.Findings, Finding{Severity: "high", Category: "coverage", File: file, Evidence: fmt.Sprint(result.Entries), Rationale: "archive entry limit exceeded", RuleID: "archive-entry-limit"})
		return false
	}
	if result.UnpackedBytes > cfg.Limits.MaxArchiveUnpackedBytes {
		result.Complete = false
		result.Findings = append(result.Findings, Finding{Severity: "high", Category: "coverage", File: file, Evidence: fmt.Sprint(result.UnpackedBytes), Rationale: "archive size limit exceeded", RuleID: "archive-size-limit"})
		return false
	}
	return true
}

func scanArchiveMember(source io.Reader, declared int64, name, virtual string, mode uint32, cfg Config, rules RuleEngine, result *ArchiveScan, depth, policyDepth int, progress archiveProgressFunc) error {
	source = archiveProgressReader{reader: source, result: result, progress: progress}
	first := make([]byte, 8192)
	n, err := io.ReadFull(source, first)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return err
	}
	first = first[:n]
	combined := io.MultiReader(bytes.NewReader(first), source)
	expectedText := mandatoryControlPath(name)
	executable := mode&0o111 != 0 || bytes.HasPrefix(first, []byte("#!"))
	if LooksLikeArchive(virtual, first) {
		if policyDepth >= 0 && depth+1 >= policyDepth {
			_, _ = io.Copy(io.Discard, combined)
			return nil
		}
		if depth+1 >= cfg.Limits.MaxArchiveDepth {
			result.Complete = false
			result.Findings = append(result.Findings, Finding{Severity: "high", Category: "coverage", File: virtual, Evidence: fmt.Sprint(depth + 1), Rationale: "nested archive depth limit reached", RuleID: "archive-depth-limit"})
			_, _ = io.Copy(io.Discard, combined)
			return nil
		}
		nestedFile, err := spoolNestedArchive(combined, declared)
		if err != nil {
			return err
		}
		defer func() {
			name := nestedFile.Name()
			_ = nestedFile.Close()
			_ = os.Remove(name)
		}()
		nested := scanArchiveWithPolicyDepth(nestedFile, virtual, cfg, rules, depth+1, policyDepth, func(value ArchiveProgress) {
			if progress != nil {
				progress(ArchiveProgress{Archives: result.Archives + value.Archives, Entries: result.Entries + value.Entries})
			}
		})
		result.Entries += nested.Entries
		result.UnpackedBytes += nested.UnpackedBytes
		result.Archives += nested.Archives
		result.Findings = append(result.Findings, nested.Findings...)
		result.Selected = append(result.Selected, nested.Selected...)
		result.Supported = result.Supported && nested.Supported
		result.Complete = result.Complete && nested.Complete
		if result.Entries > cfg.Limits.MaxArchiveEntries || result.UnpackedBytes > cfg.Limits.MaxArchiveUnpackedBytes {
			result.Complete = false
			result.Findings = append(result.Findings, Finding{Severity: "high", Category: "coverage", File: virtual, Evidence: fmt.Sprintf("entries=%d bytes=%d", result.Entries, result.UnpackedBytes), Rationale: "nested archive aggregate limit exceeded", RuleID: "nested-archive-aggregate-limit"})
		}
		if result.Archives > cfg.Limits.MaxArchives {
			result.Complete = false
			result.Findings = append(result.Findings, Finding{Severity: "high", Category: "coverage", File: virtual,
				Evidence: fmt.Sprint(result.Archives), Rationale: "aggregate nested archive count exceeded", RuleID: "archive-count-limit"})
		}
		if err := checkArchiveBudget(result, cfg); err != nil {
			return err
		}
		return nil
	}
	if probablyText(first) {
		validator := &contentValidator{}
		findings, sample, total, err := rules.ScanReader(virtual, io.TeeReader(combined, validator), cfg.Limits.MaxTextPerFile)
		if err != nil {
			return err
		}
		validator.Finish()
		if expectedText && (validator.NUL || validator.Invalid) {
			reason := "mandatory control content is not valid UTF-8 text"
			if validator.NUL {
				reason = "mandatory control content contains an embedded NUL byte"
			}
			findings = append(findings, Finding{Severity: "critical", Category: "coverage", File: virtual,
				Evidence: "content classification", Rationale: reason, RuleID: "mandatory-control-invalid", HardBlock: true})
			result.Complete = false
		}
		text := validUTF8OrReplacement(sample)
		findings = append(findings, rules.ScanSemantic(virtual, text, executable, expectedText)...)
		findings = append(findings, artifactMetadataFindings(name, text, virtual)...)
		result.Findings = append(result.Findings, findings...)
		if expectedText || executable || selectArchiveMember(name, mode, findings) {
			result.Selected = append(result.Selected, SelectedContent{virtual, text})
			if total > cfg.Limits.MaxTextPerFile {
				result.Complete = false
				result.Findings = append(result.Findings, Finding{Severity: "high", Category: "coverage", File: virtual, Evidence: fmt.Sprint(total), Rationale: "selected archive text exceeds the review text limit", RuleID: "archive-member-limit"})
			}
		}
		return nil
	}
	if expectedText || (executable && binaryFormat(first) == "") {
		_, _ = io.Copy(io.Discard, combined)
		result.Complete = false
		result.Findings = append(result.Findings, Finding{Severity: "critical", Category: "coverage", File: virtual,
			Evidence: "binary or NUL-bearing content", Rationale: "mandatory executable or control content is not fully inspectable text or a recognized executable binary",
			RuleID: "mandatory-control-invalid", HardBlock: true})
		return nil
	}
	return scanBinaryMember(combined, nil, virtual, mode, cfg, rules, result)
}

func spoolNestedArchive(source io.Reader, declared int64) (*os.File, error) {
	file, err := os.CreateTemp("", ".prolewatch-nested-archive-*")
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			name := file.Name()
			_ = file.Close()
			_ = os.Remove(name)
		}
	}()
	written, err := io.Copy(file, io.LimitReader(source, declared+1))
	if err != nil {
		return nil, err
	}
	if written != declared {
		return nil, fmt.Errorf("nested archive size differs from its header: declared=%d read=%d", declared, written)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	success = true
	return file, nil
}

func scanBinaryMember(source io.Reader, prefix []byte, virtual string, mode uint32, cfg Config, rules RuleEngine, result *ArchiveScan) error {
	captured, err := io.ReadAll(io.LimitReader(io.MultiReader(bytes.NewReader(prefix), source), cfg.Limits.BinaryStringsBytes))
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, source)
	stringsText := printableStrings(captured)
	findings := binaryStringFindings(rules.ScanText(virtual, stringsText, 0))
	result.Findings = append(result.Findings, findings...)
	format := binaryFormat(captured)
	if mode&0o111 != 0 || len(findings) > 0 || format != "" {
		result.Selected = append(result.Selected, SelectedContent{virtual, "Binary format: " + valueOr(format, "unknown") + "\nBounded printable strings:\n" + stringsText})
	}
	return nil
}

func binaryStringFindings(findings []Finding) []Finding {
	result := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.HardBlock {
			result = append(result, finding)
		}
	}
	return result
}

func packageArchiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".pkg.tar", ".pkg.tar.gz", ".pkg.tar.xz", ".pkg.tar.zst"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func scanCompressedStream(source io.Reader, head []byte, display string, cfg Config, rules RuleEngine, result *ArchiveScan, progress archiveProgressFunc) error {
	decompressed, closer, err := compressedReader(source, head)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer.Close()
	}
	virtual := display + "!/<compressed-stream>"
	result.Entries++
	emitArchiveProgress(result, progress)
	limited := &countingLimitReader{Reader: archiveProgressReader{reader: decompressed, result: result, progress: progress}, Limit: cfg.Limits.MaxArchiveUnpackedBytes + 1}
	first := make([]byte, 8192)
	n, readErr := io.ReadFull(limited, first)
	if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
		return readErr
	}
	first = first[:n]
	combined := io.MultiReader(bytes.NewReader(first), limited)
	if inner := archiveFormat(first); inner != "" {
		result.Complete = false
		return fmt.Errorf("compressed stream contains unsupported nested %s archive", inner)
	}
	mandatory := mandatoryControlPath(display) || bytes.HasPrefix(first, []byte("#!"))
	if !probablyText(first) {
		if mandatory {
			_, _ = io.Copy(io.Discard, combined)
			result.Complete = false
			result.Findings = append(result.Findings, Finding{Severity: "critical", Category: "coverage", File: virtual,
				Evidence: "binary or NUL-bearing compressed control content", Rationale: "mandatory compressed executable or control content is not fully inspectable text",
				RuleID: "mandatory-control-invalid", HardBlock: true})
			return nil
		}
		if err := scanBinaryMember(combined, nil, virtual, 0, cfg, rules, result); err != nil {
			return err
		}
		result.UnpackedBytes = limited.Count
		if limited.Count > cfg.Limits.MaxArchiveUnpackedBytes {
			result.Complete = false
			return errors.New("gzip stream exceeds unpacked size limit")
		}
		return nil
	}
	validator := &contentValidator{}
	findings, sample, _, err := rules.ScanReader(virtual, io.TeeReader(combined, validator), cfg.Limits.MaxTextPerFile)
	if err != nil {
		return err
	}
	validator.Finish()
	if mandatory && (validator.NUL || validator.Invalid) {
		result.Complete = false
		result.Findings = append(result.Findings, Finding{Severity: "critical", Category: "coverage", File: virtual,
			Evidence: "invalid compressed control content", Rationale: "mandatory compressed control content is not valid NUL-free UTF-8 text",
			RuleID: "mandatory-control-invalid", HardBlock: true})
	}
	result.UnpackedBytes = limited.Count
	if limited.Count > cfg.Limits.MaxArchiveUnpackedBytes {
		result.Complete = false
		return errors.New("gzip stream exceeds unpacked size limit")
	}
	text := validUTF8OrReplacement(sample)
	findings = append(findings, artifactMetadataFindings(display, text, virtual)...)
	result.Findings = append(result.Findings, findings...)
	if mandatory || selectArchiveMember(display, 0, findings) {
		result.Selected = append(result.Selected, SelectedContent{virtual, text})
	}
	if limited.Count > cfg.Limits.MaxTextPerFile && (len(findings) > 0 || importantArtifactName(path.Base(display))) {
		result.Complete = false
		result.Findings = append(result.Findings, Finding{Severity: "high", Category: "coverage", File: virtual, Evidence: fmt.Sprint(limited.Count), Rationale: "selected gzip text exceeds review text limit", RuleID: "archive-member-limit"})
	}
	return nil
}

func checkArchiveBudget(result *ArchiveScan, cfg Config) error {
	if len(result.Findings) > cfg.Limits.MaxFindings {
		return errors.New("aggregate archive finding limit exceeded")
	}
	if result.Archives > cfg.Limits.MaxArchives {
		return errors.New("aggregate nested archive count exceeded")
	}
	return nil
}

type countingLimitReader struct {
	Reader       io.Reader
	Limit, Count int64
}

func (r *countingLimitReader) Read(p []byte) (int, error) {
	if r.Count >= r.Limit {
		return 0, io.EOF
	}
	if int64(len(p)) > r.Limit-r.Count {
		p = p[:r.Limit-r.Count]
	}
	n, err := r.Reader.Read(p)
	r.Count += int64(n)
	return n, err
}

func archiveModeFindings(name string, mode uint32, pax map[string]string, virtual string, result *ArchiveScan) {
	if mode&0o6000 != 0 {
		result.Findings = append(result.Findings, Finding{Severity: "critical", Category: "privilege_escalation", File: virtual, Evidence: fmt.Sprintf("%#o", mode), Rationale: "package artifact contains a setuid or setgid entry", RuleID: "artifact-setid", HardBlock: true})
	}
	for key := range pax {
		if strings.HasSuffix(key, "security.capability") {
			result.Findings = append(result.Findings, Finding{Severity: "critical", Category: "privilege_escalation", File: virtual, Evidence: "security.capability", Rationale: "package artifact assigns Linux file capabilities", RuleID: "artifact-capability", HardBlock: true})
			break
		}
	}
	if privilegedPackagePath(name) {
		result.Findings = append(result.Findings, Finding{Severity: "medium", Category: "persistence", File: virtual, Evidence: name, Rationale: "package artifact installs a privileged integration surface", RuleID: "artifact-integration"})
	}
}

func probablyText(data []byte) bool {
	return !bytes.Contains(data, []byte{0}) && binaryFormat(data) == ""
}

func selectArchiveMember(name string, mode uint32, findings []Finding) bool {
	lower, base := strings.ToLower(path.Ext(name)), strings.ToLower(path.Base(name))
	important := map[string]bool{".sh": true, ".bash": true, ".zsh": true, ".py": true, ".pl": true, ".rb": true, ".js": true, ".ts": true, ".lua": true, ".patch": true, ".diff": true, ".service": true, ".install": true, ".spec": true}[lower]
	important = important || map[string]bool{"makefile": true, "cmakelists.txt": true, "meson.build": true, "build.rs": true, "setup.py": true, "package.json": true}[base]
	return mode&0o111 != 0 || important || len(findings) > 0
}

func mandatoryControlPath(name string) bool {
	lower, base := strings.ToLower(path.Ext(name)), strings.ToLower(path.Base(name))
	if privilegedPackagePath(name) || importantArtifactName(path.Base(name)) {
		return true
	}
	return map[string]bool{
		".install": true, ".patch": true, ".diff": true, ".sh": true, ".bash": true, ".zsh": true,
		".py": true, ".pl": true, ".rb": true, ".js": true, ".ts": true, ".lua": true,
		".spec":    true,
		".service": true, ".socket": true, ".timer": true, ".path": true, ".target": true,
		".mount": true, ".automount": true, ".slice": true, ".scope": true, ".device": true,
		".swap": true, ".rules": true, ".hook": true, ".desktop": true, ".conf": true,
	}[lower] || map[string]bool{
		"pkgbuild": true, ".srcinfo": true, "makefile": true, "cmakelists.txt": true,
		"meson.build": true, "build.rs": true, "setup.py": true, "pyproject.toml": true,
		"package.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true,
		".npmrc": true, "cargo.toml": true, "go.mod": true, "pip.conf": true,
	}[base]
}

func privilegedPackagePath(name string) bool {
	clean := strings.TrimPrefix(path.Clean(name), "./")
	if clean == ".INSTALL" {
		return true
	}
	for _, prefix := range []string{
		"usr/lib/systemd/system/", "usr/lib/systemd/user/", "usr/lib/systemd/system-generators/",
		"usr/lib/systemd/user-generators/", "usr/lib/systemd/system-environment-generators/",
		"usr/lib/systemd/user-environment-generators/", "usr/lib/udev/rules.d/", "usr/share/libalpm/hooks/",
		"usr/lib/tmpfiles.d/", "usr/lib/sysusers.d/", "etc/systemd/system/", "etc/systemd/user/",
		"etc/udev/rules.d/", "etc/tmpfiles.d/", "etc/sysusers.d/", "etc/pam.d/", "etc/sudoers.d/",
		"etc/cron.d/", "etc/cron.daily/", "etc/cron.hourly/", "etc/cron.weekly/", "etc/cron.monthly/",
	} {
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return false
}

func artifactMetadataFindings(name, text, virtual string) []Finding {
	base := path.Base(name)
	var findings []Finding
	if base == ".PKGINFO" {
		keys := map[string]bool{}
		for _, line := range strings.Split(text, "\n") {
			if key, _, ok := strings.Cut(line, " = "); ok {
				keys[key] = true
			}
		}
		var missing []string
		for _, key := range []string{"pkgname", "pkgver", "arch"} {
			if !keys[key] {
				missing = append(missing, key)
			}
		}
		if len(missing) > 0 {
			findings = append(findings, Finding{Severity: "high", Category: "coverage", File: virtual, Evidence: strings.Join(missing, ","), Rationale: "package metadata is missing required fields", RuleID: "pkginfo-missing"})
		}
	} else if base == ".BUILDINFO" && !strings.Contains(text, "builddate = ") {
		findings = append(findings, Finding{Severity: "medium", Category: "package_metadata", File: virtual, Evidence: "builddate", Rationale: "build metadata is incomplete", RuleID: "buildinfo-incomplete"})
	} else if base == ".MTREE" {
		for index, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "mode=4") || strings.Contains(line, "mode=2") || strings.Contains(line, "security.capability") {
				ln := index + 1
				findings = append(findings, Finding{Severity: "critical", Category: "privilege_escalation", File: virtual, Line: &ln, Evidence: truncate(line, 320), Rationale: "package mtree records privileged mode or capabilities", RuleID: "mtree-privileged", HardBlock: true})
			}
		}
	}
	return findings
}

func importantArtifactName(name string) bool {
	return name == ".MTREE" || name == ".PKGINFO" || name == ".BUILDINFO" || name == ".INSTALL"
}

func printableStrings(data []byte) string {
	var lines []string
	var current []byte
	flush := func() {
		if len(current) >= 4 {
			lines = append(lines, string(current))
		}
		current = nil
	}
	for _, value := range data {
		if value == 9 || (value >= 32 && value <= 126) {
			current = append(current, value)
		} else {
			flush()
		}
	}
	flush()
	return strings.Join(lines, "\n")
}

func binaryFormat(data []byte) string {
	if bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) {
		return "ELF"
	}
	if bytes.HasPrefix(data, []byte("MZ")) {
		return "PE"
	}
	if len(data) >= 4 {
		magic := binary.BigEndian.Uint32(data[:4])
		if magic == 0xfeedface || magic == 0xcefaedfe || magic == 0xfeedfacf || magic == 0xcffaedfe {
			return "Mach-O"
		}
	}
	return ""
}

func truncate(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func truncateTail(value string, limit int) string {
	const marker = "[earlier output omitted]\n"
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	if limit <= len(marker) {
		return value[len(value)-limit:]
	}
	return marker + value[len(value)-(limit-len(marker)):]
}
func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
