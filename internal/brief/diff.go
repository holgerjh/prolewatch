package brief

import (
	"bytes"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var unifiedDiffHunkHeaderRE = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@(?: .*)?$`)

func unifiedDiffPath(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".patch", ".diff":
		return true
	default:
		return false
	}
}

// unifiedDiffBehaviorText masks lines a valid unified diff removes while
// preserving every byte and newline position. Those lines describe behavior
// that the patch takes away, not behavior it introduces or leaves active.
//
// This deliberately recognises only complete, ordinary unified diffs. Any
// ambiguity returns the original text and false, causing the caller to keep the
// conservative raw scan. Prompt-injection and content-safety rules receive the
// original text separately even when this behavior view is accepted.
func unifiedDiffBehaviorText(name, text string) (string, bool) {
	if !unifiedDiffPath(name) || text == "" {
		return text, false
	}
	raw := []byte(text)
	masked := append([]byte(nil), raw...)
	var oldRemaining, newRemaining uint64
	inHunk := false
	lastHunkData := false
	oldHeader := false
	headerPair := false
	pendingHunk := false
	sawHunk := false

	for offset := 0; offset < len(raw); {
		newline := bytes.IndexByte(raw[offset:], '\n')
		lineEnd, next := len(raw), len(raw)
		if newline >= 0 {
			lineEnd = offset + newline
			next = lineEnd + 1
		}
		contentEnd := lineEnd
		if contentEnd > offset && raw[contentEnd-1] == '\r' {
			contentEnd--
		}
		line := string(raw[offset:contentEnd])

		if inHunk {
			if line == `\ No newline at end of file` {
				if !lastHunkData {
					return text, false
				}
				lastHunkData = false
				offset = next
				continue
			}
			if oldRemaining == 0 && newRemaining == 0 {
				inHunk = false
				lastHunkData = false
			} else {
				if len(line) == 0 {
					return text, false
				}
				switch line[0] {
				case ' ':
					if oldRemaining == 0 || newRemaining == 0 {
						return text, false
					}
					oldRemaining--
					newRemaining--
				case '-':
					if oldRemaining == 0 {
						return text, false
					}
					oldRemaining--
					for index := offset; index < lineEnd; index++ {
						masked[index] = ' '
					}
				case '+':
					if newRemaining == 0 {
						return text, false
					}
					newRemaining--
				default:
					return text, false
				}
				lastHunkData = true
				offset = next
				continue
			}
		}

		switch {
		case strings.HasPrefix(line, "@@@") || strings.HasPrefix(line, "diff --combined ") || strings.HasPrefix(line, "diff --cc "):
			return text, false
		case strings.HasPrefix(line, "@@"):
			if !headerPair {
				return text, false
			}
			oldCount, newCount, ok := unifiedDiffHunkCounts(line)
			if !ok || oldCount == 0 && newCount == 0 {
				return text, false
			}
			oldRemaining, newRemaining = oldCount, newCount
			inHunk = true
			lastHunkData = false
			pendingHunk = false
			sawHunk = true
		case strings.HasPrefix(line, "--- "):
			if oldHeader || pendingHunk {
				return text, false
			}
			oldHeader = true
			headerPair = false
		case strings.HasPrefix(line, "+++ "):
			if !oldHeader {
				return text, false
			}
			oldHeader = false
			headerPair = true
			pendingHunk = true
		case oldHeader:
			return text, false
		case line == `\ No newline at end of file`, line == "GIT binary patch", strings.HasPrefix(line, "Binary files "):
			return text, false
		case line != "" && (line[0] == '-' || line[0] == '+' || line[0] == ' '):
			// Hunk-looking content outside a counted hunk makes the document
			// ambiguous. Do not grant it the inactive-line interpretation.
			return text, false
		}
		offset = next
	}

	if oldHeader || pendingHunk || !sawHunk || inHunk && (oldRemaining != 0 || newRemaining != 0) {
		return text, false
	}
	return string(masked), true
}

func unifiedDiffHunkCounts(line string) (uint64, uint64, bool) {
	match := unifiedDiffHunkHeaderRE.FindStringSubmatch(line)
	if match == nil {
		return 0, 0, false
	}
	// Parse the start positions too. They do not affect masking, but accepting an
	// overflowing coordinate would mean accepting a malformed hunk header.
	if _, err := strconv.ParseUint(match[1], 10, 64); err != nil {
		return 0, 0, false
	}
	if _, err := strconv.ParseUint(match[3], 10, 64); err != nil {
		return 0, 0, false
	}
	oldCount, ok := unifiedDiffCount(match[2])
	if !ok {
		return 0, 0, false
	}
	newCount, ok := unifiedDiffCount(match[4])
	return oldCount, newCount, ok
}

func unifiedDiffCount(value string) (uint64, bool) {
	if value == "" {
		return 1, true
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed, err == nil
}
