package audit

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/holgerjh/prolewatch/internal/brief"

	"golang.org/x/sys/unix"
)

type terminalColorLevel int

const (
	// These levels select ANSI encodings only; semantic roles such as "red" or
	// "muted" remain stable so every renderer has the same presentation grammar.
	terminalColorNone terminalColorLevel = iota
	terminalColor16
	terminalColor256
	terminalColorTrue
)

type terminalCapabilities struct {
	Interactive bool
	Unicode     bool
	Color       terminalColorLevel
	Columns     int
}

type terminalRenderer struct {
	out  io.Writer
	caps terminalCapabilities
}

// TerminalPresentation exposes the shared presentation grammar to the other
// first-party command packages without exposing ANSI construction primitives.
type TerminalPresentation struct{ renderer terminalRenderer }

func NewTerminalPresentation(cfg Config, out io.Writer) TerminalPresentation {
	return TerminalPresentation{renderer: newTerminalRenderer(cfg, out)}
}

func (p TerminalPresentation) Enabled() bool { return p.renderer.enabled() }

func (p TerminalPresentation) Header(title, stamp string, success bool) string {
	role := "red"
	if success {
		role = "green"
	}
	return p.renderer.paint("blue", p.renderer.anchor()) + " " + p.renderer.paint("bold", terminalInline(title, 200)) + "  " + p.renderer.stamp(terminalInline(stamp, 40), role)
}

func (p TerminalPresentation) Status(status, message string, success bool) string {
	role, marker := "red", p.renderer.anchor()
	if success {
		role, marker = "green", p.renderer.bullet()
	}
	return p.renderer.paint(role, marker) + " " + terminalInline(message, 4000) + "  " + p.renderer.stamp(terminalInline(status, 40), role)
}

func (p TerminalPresentation) Detail(message string) string {
	return "  " + p.renderer.paint("muted", p.renderer.branch()) + " " + terminalInline(message, 4000)
}

func terminalInline(value any, limit int) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(TerminalText(value, limit))
}

func newTerminalRenderer(cfg Config, out io.Writer) terminalRenderer {
	if cfg.Terminal.Style != TerminalStyleBrand {
		return terminalRenderer{out: out}
	}
	return terminalRenderer{out: out, caps: detectTerminalCapabilities(out, os.Getenv, os.LookupEnv)}
}

func detectTerminalCapabilities(out io.Writer, getenv func(string) string, lookupEnv func(string) (string, bool)) terminalCapabilities {
	// Styling is enabled only for a real terminal. Redirected reports stay plain,
	// deterministic text with no control bytes that could corrupt logs or JSON.
	file, ok := out.(interface{ Fd() uintptr })
	term := strings.ToLower(getenv("TERM"))
	if !ok || term == "" || term == "dumb" || !isTerminalFD(file.Fd()) {
		return terminalCapabilities{}
	}
	caps := terminalEnvironmentCapabilities(getenv, lookupEnv)
	if size, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ); err == nil && size.Col > 1 {
		caps.Columns = int(size.Col)
	}
	return caps
}

func terminalEnvironmentCapabilities(getenv func(string) string, lookupEnv func(string) (string, bool)) terminalCapabilities {
	term := strings.ToLower(getenv("TERM"))
	if term == "" || term == "dumb" {
		return terminalCapabilities{}
	}
	caps := terminalCapabilities{Interactive: true, Unicode: terminalHasUnicode(getenv)}
	if _, present := lookupEnv("NO_COLOR"); present {
		return caps
	}
	colorTerm := strings.ToLower(getenv("COLORTERM"))
	switch {
	case strings.Contains(colorTerm, "truecolor") || strings.Contains(colorTerm, "24bit") || strings.Contains(term, "direct"):
		caps.Color = terminalColorTrue
	case strings.Contains(term, "256color"):
		caps.Color = terminalColor256
	default:
		caps.Color = terminalColor16
	}
	return caps
}

func isTerminalFile(file *os.File) bool {
	if file == nil {
		return false
	}
	return isTerminalFD(file.Fd())
}

func isTerminalFD(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}

func terminalHasUnicode(getenv func(string) string) bool {
	locale := getenv("LC_ALL")
	if locale == "" {
		locale = getenv("LC_CTYPE")
	}
	if locale == "" {
		locale = getenv("LANG")
	}
	locale = strings.ToLower(locale)
	return strings.Contains(locale, "utf-8") || strings.Contains(locale, "utf8")
}

func (r terminalRenderer) enabled() bool { return r.caps.Interactive }

func (r terminalRenderer) glyph(unicode, ascii string) string {
	if r.caps.Unicode {
		return unicode
	}
	return ascii
}

func (r terminalRenderer) paint(role, value string) string {
	if r.caps.Color == terminalColorNone || value == "" {
		return value
	}
	code := ""
	switch r.caps.Color {
	case terminalColorTrue:
		code = map[string]string{
			"red": "1;38;2;224;90;95", "blue": "38;2;23;147;209", "amber": "38;2;208;163;91",
			"green": "38;2;120;170;130", "muted": "38;2;198;193;188", "bold": "1",
		}[role]
	case terminalColor256:
		code = map[string]string{"red": "1;38;5;167", "blue": "38;5;32", "amber": "38;5;179", "green": "38;5;108", "muted": "38;5;250", "bold": "1"}[role]
	case terminalColor16:
		code = map[string]string{"red": "1;31", "blue": "36", "amber": "33", "green": "32", "muted": "90", "bold": "1"}[role]
	}
	if code == "" {
		return value
	}
	// ESC [ ... m begins an ANSI SGR style; ESC [ 0 m resets it so untrusted
	// report text cannot inherit formatting beyond this rendered fragment.
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func (r terminalRenderer) bullet() string { return r.glyph("•", "*") }
func (r terminalRenderer) anchor() string { return r.glyph("◆", "#") }
func (r terminalRenderer) branch() string { return r.glyph("└─", "\\-") }
func (r terminalRenderer) fork() string   { return r.glyph("├─", "+-") }
func (r terminalRenderer) pipe() string   { return r.glyph("│", "|") }
func (r terminalRenderer) divider() string {
	return " " + r.glyph("·", "-") + " "
}

func (r terminalRenderer) stamp(label, role string) string {
	return r.paint(role, "[ "+label+" ]")
}

func (r terminalRenderer) activation() string {
	if !r.enabled() {
		return ""
	}
	return r.paint("blue", r.anchor()) + " " + r.paint("bold", "PROLEWATCH ACTIVE") + r.paint("muted", r.divider()+"reviewing this yay transaction")
}

func (r terminalRenderer) successLine(message string) string {
	if !r.enabled() {
		return message
	}
	return r.paint("green", r.bullet()) + " " + message + "  " + r.stamp("READY", "green")
}

func (r terminalRenderer) runningLine(message string) string {
	message = terminalInline(message, 4000)
	if !r.enabled() {
		return "Prolewatch: " + message
	}
	return r.paint("amber", r.bullet()) + " " + message + "  " + r.stamp("RUNNING", "amber")
}

func (r terminalRenderer) detailLine(message string) string {
	if !r.enabled() {
		return message
	}
	return r.paint("muted", r.branch()) + " " + message
}

func (r terminalRenderer) errorLine(message string) string {
	if !r.enabled() {
		return "prolewatch: " + message
	}
	return r.paint("red", r.anchor()) + " " + r.paint("bold", "PROLEWATCH") + "  " + r.stamp("BLOCK", "red") + " " + message
}

// stampedLine is errorLine with the verdict word chosen by the caller.
//
// BLOCK is a decision about the package. A build that failed on its own defect,
// or that hit a resource ceiling, is not a decision at all, and printing the
// same red BLOCK for both told the user that a broken Makefile and a hostile
// package were the same kind of event.
func (r terminalRenderer) stampedLine(label, role, message string) string {
	if !r.enabled() {
		return "prolewatch: " + label + ": " + message
	}
	return r.paint(role, r.anchor()) + " " + r.paint("bold", "PROLEWATCH") + "  " + r.stamp(label, role) + " " + message
}

func (r terminalRenderer) artifactReadyLine(count int) string {
	if !r.enabled() {
		return ""
	}
	return r.paint("green", r.bullet()) + fmt.Sprintf(" %d reviewed artifact(s) bound to the report  ", count) + r.stamp("READY", "green")
}

func (r terminalRenderer) containedMakepkgOutputHeader(packageBase, phase string) string {
	packagePhase := terminalInline(packageBase, 4096)
	if phase = terminalInline(phase, 100); phase != "" {
		packagePhase += " / " + phase
	}
	if !r.enabled() {
		return "Prolewatch: contained makepkg output begins: " + packagePhase + "; package-authored text follows; terminal controls escaped"
	}
	header := r.paint("blue", r.anchor()) + " " + r.paint("bold", "PROLEWATCH") + r.paint("muted", r.divider()+"CONTAINED MAKEPKG OUTPUT")
	detail := r.paint("muted", r.fork()) + " " + packagePhase + r.paint("muted", r.divider()+"package-authored text follows"+r.divider()+"captured in sandbox"+r.divider()+"terminal controls escaped")
	return header + "\n" + detail
}

func (r terminalRenderer) containedMakepkgOutputGutter() string {
	if !r.enabled() {
		return "| "
	}
	return r.paint("blue", r.pipe()) + " "
}

func (r terminalRenderer) containedMakepkgOutputFooter() string {
	if !r.enabled() {
		return "Prolewatch: contained makepkg output ended; guard resumes"
	}
	return r.paint("blue", r.anchor()) + " " + r.paint("bold", "PROLEWATCH") +
		r.paint("muted", r.divider()+"CONTAINED MAKEPKG OUTPUT ENDED"+r.divider()+"guard resumes")
}

// phaseName is the human name for a report phase.
//
// "pre", "post" and "artifact" are this program's internal vocabulary. Printed
// raw they make three different gates look like one block shown three times,
// which is exactly how it reads to somebody who has not read the architecture
// document.
func phaseName(phase string) string {
	switch phase {
	case "pre":
		return "recipe"
	case "post":
		return "sources"
	case "artifact":
		return "built package"
	}
	return terminalInline(phase, 100)
}

// phaseMoment says where in the transaction the reader is standing. The name
// alone says what is being looked at; this says why it is being looked at now,
// which is the half that answers "haven't I already seen this?".
func phaseMoment(phase string) string {
	switch phase {
	case "pre":
		return "before any source is fetched"
	case "post":
		return "before the build runs"
	case "artifact":
		return "before pacman installs it"
	}
	return ""
}

func (r terminalRenderer) guardComplete(report *Report) string {
	if report == nil {
		return ""
	}
	packagePhase := terminalInline(report.PackageBase, 4096) + " / " + terminalInline(report.Phase, 100)
	if !r.enabled() {
		return "Prolewatch phase complete: " + packagePhase + "; " + phaseHandoff(report.Phase)
	}
	return r.paint("blue", r.anchor()) + " " + r.paint("bold", "PROLEWATCH") +
		r.paint("muted", r.divider()+"PHASE COMPLETE"+r.divider()) +
		terminalInline(report.PackageBase, 4096) + r.paint("muted", " · "+phaseName(report.Phase)) +
		r.paint("muted", r.divider()+phaseHandoff(report.Phase))
}

func phaseHandoff(phase string) string {
	switch phase {
	case "pre":
		return "yay resumes · next: source acquisition"
	case "post":
		return "yay resumes · next: contained build"
	default:
		return "yay resumes"
	}
}

// report renders a briefing that stands alone: it tells the user how to act
// from another shell, because nothing else is going to ask them.
func (r terminalRenderer) report(report *Report) string {
	return r.reportWithPrompt(report, false)
}

// reportWithPrompt renders a briefing that is about to be followed by an
// interactive decision. It omits the command-line instructions, because
// printing "run prolewatch approve ..." immediately above a prompt that asks
// the same question tells the user to go and do something they are already
// being offered.
func (r terminalRenderer) reportWithPrompt(report *Report, promptFollows bool) string {
	return r.reportWithHandoff(report, promptFollows, false)
}

func (r terminalRenderer) reportWithHandoff(report *Report, promptFollows, handoff bool) string {
	if !r.enabled() {
		return renderReportText(report, promptFollows)
	}
	// The briefing is ordered for someone deciding whether to install, not for
	// an auditor reading afterwards: what this package is, what is wrong with
	// it, what protects you anyway, what to do about it - and only then the
	// identifiers, in a dim footer where they stay available without competing.
	//
	// Provenance identifiers stay in the footer so the decision, material,
	// findings, protections, and next action remain the visual hierarchy.
	decision, role := "NEEDS YOUR DECISION", "amber"
	switch {
	case report.Decision == "allow" && report.Overridden:
		decision, role = "APPROVED BY YOU", "green"
	case report.Decision == "allow" && report.CarriedDecision != nil:
		decision, role = "NO NEW DECISION NEEDED", "green"
	case report.Decision == "allow":
		decision, role = "NO BLOCKING FINDINGS", "green"
	case !report.ApprovalEligible:
		// Structural failures are the only ones no approval can cross.
		decision, role = "STRUCTURAL FAILURE", "red"
	}
	packagePhase := terminalInline(report.PackageBase, 4096) + " · " + phaseName(report.Phase)
	header := r.paint("bold", terminalInline(report.PackageBase, 4096)) +
		r.paint("muted", " · "+phaseName(report.Phase))
	if moment := phaseMoment(report.Phase); moment != "" {
		header += r.paint("muted", r.divider()+moment)
	}
	// The stamp already states the outcome and the sections below carry the
	// evidence. Repeating policySummary here produced contradictions such as
	// "NEEDS YOUR DECISION" immediately followed by "No blocking findings".
	// Keep the summary in the stored/plain report, where it remains useful to
	// scripts, but do not spend a prominent line on it in the interactive card.
	lines := []string{header + "  " + r.stamp(decision, role)}

	// 0. What is being installed, what changed, and where its material comes
	//    from. These facts belong to one overview rather than appearing as
	//    unlabelled peers of the Findings section below.
	overview := []string{}
	if transition := packageTransition(report, r.glyph("→", "->"), r.divider()); transition != "" {
		overview = append(overview, "  "+r.paint("muted", r.bullet())+" change    "+transition)
	}
	if changed := changedMaterial(report, r.divider(), 4); changed != "" {
		overview = append(overview, "    "+r.paint("amber", r.branch())+" "+changed)
	}

	// Source provenance makes the findings below interpretable: the same
	// critical finding reads differently in a package pulling only from a known
	// host.
	if summary := sourceBriefing(report); summary != "" {
		overview = append(overview, "  "+r.paint("muted", r.bullet())+" sources   "+summary)
	}
	if binding := brief.SourceSummary(report.Sources, report.SourceVerification); binding != "" {
		overview = append(overview, "    "+r.paint("muted", r.branch())+" "+terminalInline(binding, 2000))
	}
	if len(report.AcquiredHosts) > 0 {
		overview = append(overview, "    "+r.paint("muted", r.branch())+" contacted "+terminalInline(strings.Join(report.AcquiredHosts, ", "), 2000))
	}
	if len(overview) > 0 {
		lines = append(lines, "", r.paint("bold", "Overview"))
		lines = append(lines, overview...)
	}

	// 1. What is wrong with it. The evidence carries the signal, so it is the
	//    prominent half; the category taxonomy is the tool's vocabulary, not
	//    the reader's, and rides along dimmed. "DETERMINISTIC" is printed only
	//    when a finding did not come from the deterministic pass, because a
	//    label on every line conveys nothing.
	if len(report.Findings) > 0 {
		lines = append(lines, "", r.paint("bold", "Findings")+r.paint("muted", r.divider()+"critical to info"))
		carriedIDs := carriedFindingIDSet(report.CarriedDecision)
		for _, item := range report.Findings {
			location := terminalInline(item.File, 4096)
			if item.Line != nil {
				location += fmt.Sprintf(":%d", *item.Line)
			}
			severity := strings.ToUpper(terminalInline(item.Severity, 40))
			findingRole := "amber"
			if item.Severity == "critical" || item.Severity == "high" {
				findingRole = "red"
			}
			origin := findingOrigin(item)
			carried := carriedIDs[findingGuidanceID(item)]
			if carried {
				findingRole = "blue"
				origin += " · approved at recipe gate"
			}
			// Every finding names where it came from, and the label is painted
			// with the severity rather than dimmed: an AI finding is exactly as
			// visible as a deterministic one of the same severity. A muted mark
			// on the AI half only was the least legible way to draw the one
			// distinction the reader actually needs.
			rationale := terminalInline(item.Rationale, 2000)
			head := "  " + r.paint(findingRole, r.anchor()+" "+severity+" ("+origin+"):") + " " + rationale
			if carried {
				head = "  " + r.paint("blue", r.anchor()+" "+severity+" ("+origin+"): "+rationale)
			}
			lines = append(lines, head)
			detail := location + r.divider() + terminalInline(item.Category, 80)
			if item.Evidence != "" {
				detail += "  " + terminalInline(item.Evidence, 320)
			}
			if carried {
				detail += r.divider() + "exact bytes unchanged"
			}
			lines = append(lines, "    "+r.paint("muted", r.branch()+" "+detail))
		}
	}
	if verdictsHaveCoverageNotes(report.Reviewer.Verdicts) {
		lines = append(lines, "", r.paint("bold", "AI coverage gaps"))
		for batch, verdict := range report.Reviewer.Verdicts {
			for _, note := range verdict.CoverageNotes {
				lines = append(lines, "  "+r.paint("amber", r.anchor())+" batch "+strconv.Itoa(batch+1)+r.divider()+terminalInline(note, 1000))
			}
		}
	}
	if status, statusRole := aiReviewStatus(report, r.divider()); status != "" {
		heading := r.paint("bold", "AI review")
		marker := r.bullet()
		if report.Reviewer.Error != "" {
			heading += "  " + r.stamp("DEGRADED", "amber")
			marker = r.anchor()
		}
		lines = append(lines, "", heading)
		lines = append(lines, "  "+r.paint(statusRole, marker)+" "+status)
		if note := aiReviewScopeNote(report); note != "" {
			lines = append(lines, "    "+r.paint("muted", r.branch()+" "+note))
		}
	}

	// 2. What protects the user or happens next. Without this a critical
	//    build-time finding
	//    reads as "you are about to be compromised" when the honest reading is
	//    "this will run, and it will run with nothing worth stealing in reach".
	//    Keep the claim to one scan-friendly line. Concrete destinations and
	//    known fetch operations belong to the intervention prompt that appears
	//    only if the contained build actually asks for network access.
	// containmentSummary is a constant. It reads nothing from this report and
	// says the same words about every package, so on every gate of every
	// package in a ten-package transaction it stops being information and
	// becomes advertising - and the reader learns to skip the block it sits in.
	//
	// Its stated purpose is to be the honest counterweight to an alarming
	// finding: "this will run, and it will run with nothing worth stealing in
	// reach". Print it where that work exists - when the user is actually being
	// asked to decide, and at the built-package gate, which is the last thing
	// said before pacman receives the archive.
	//
	// "Alarming" is not the same as "blocked": a report can allow and still
	// carry a critical finding, and that is the case the counterweight exists
	// for. A package whose worst news is a medium build-system hook does not
	// need reassuring about.
	alarming := report.Decision != "allow"
	for _, finding := range report.Findings {
		if finding.Severity == "critical" || finding.Severity == "high" {
			alarming = true
			break
		}
	}
	showContainment := alarming || report.Phase == "artifact"
	if showContainment || len(report.StrippedSurfaces) > 0 {
		protectionHeading := "Next"
		if report.Phase == "artifact" {
			protectionHeading = "Build protection"
		}
		lines = append(lines, "", r.paint("bold", protectionHeading))
		if showContainment {
			lines = append(lines, "  "+r.paint("green", r.bullet())+" sandbox   "+containmentSummary(report, r.divider()))
		}
		for _, stripped := range report.StrippedSurfaces {
			lines = append(lines, "    "+r.paint("amber", r.branch())+" stripped  "+terminalInline(strings.Join(stripped.Members, ", "), 2000)+r.divider()+"from "+terminalInline(stripped.Package, 512))
		}
	}

	// 3. What to do. The action, not a footnote - unless an interactive prompt
	//    is about to ask the same question, in which case saying it twice sends
	//    the user to another shell for no reason.
	if report.Decision == "block" && report.ApprovalEligible && !promptFollows {
		lines = append(lines, "", r.paint("amber", r.anchor())+" "+r.paint("bold", "To approve this exact snapshot, once:"))
		lines = append(lines, "    prolewatch approve "+terminalInline(report.ReportID, 4096))
	}
	// A structural failure prints its recovery even when a prompt follows.
	// promptFollows suppresses the approve line because the prompt is about to
	// ask that same question; no prompt ever offers this one, so suppressing it
	// here would restore the dead end it exists to close.
	for _, class := range structuralRecovery(report) {
		lines = append(lines, "", r.paint("red", r.anchor())+" "+r.paint("bold", class.title))
		for _, step := range class.steps {
			lines = append(lines, "    "+r.paint("muted", r.branch())+" "+step)
		}
	}

	// 4. Identifiers, dimmed. Available for correlation, not competing for
	//    attention with the decision.
	review := terminalInline(report.Reviewer.Mode, 100)
	if report.Reviewer.Mode == ReviewModeAI {
		review += " " + terminalInline(report.Reviewer.Provider, 100) + "/" + terminalInline(report.Reviewer.Model, 256)
		if lowest := lowestVerdictConfidence(report.Reviewer.Verdicts); lowest != "" {
			review += " confidence " + terminalInline(lowest, 20) + ", minimum " + terminalInline(report.Reviewer.MinimumConfidence, 20)
		}
	}
	content := report.ContentHash
	if content == "" {
		content = "unavailable"
	}
	footerParts := []string{fmt.Sprintf("%d files", report.Coverage.FilesSeen), humanBytes(report.Coverage.BytesSeen)}
	if selection := aiSelectionSummary(report); selection != "" {
		footerParts = append(footerParts, selection)
	}
	footerParts = append(footerParts, review)
	footer := strings.Join(footerParts, r.divider())
	lines = append(lines, "", r.paint("muted", footer))
	identifierLine := "report " + terminalInline(report.ReportID, 4096) + r.divider() + "content " + terminalInline(content, 128)
	if reportInspectionHint(report, promptFollows) {
		identifierLine += r.divider() + "inspect: prolewatch inspect --latest"
	}
	lines = append(lines, r.paint("muted", identifierLine))
	return r.fullReportBlock(lines, packagePhase, report.Phase, handoff)
}

func reportInspectionHint(report *Report, promptFollows bool) bool {
	return report != nil && len(report.Findings) > 0 && !promptFollows
}

// fullReportBlock gives a complete Prolewatch briefing one continuous visual
// owner. The outer blue rail encloses summary, sources, findings and footer;
// severity markers inside it retain their red/amber meaning. Compact one-line
// phase results deliberately do not get a frame.
func (r terminalRenderer) fullReportBlock(lines []string, packagePhase, phase string, handoff bool) string {
	if !r.enabled() || len(lines) < 2 {
		return strings.Join(lines, "\n")
	}
	framed := make([]string, 0, len(lines)+3)
	framed = append(framed, r.paint("blue", r.anchor())+" "+r.paint("bold", "PROLEWATCH")+r.paint("muted", r.divider()+"PACKAGE REVIEW"))
	for index := 0; index < len(lines); index++ {
		marker := r.pipe()
		if index == 0 {
			marker = r.fork()
		}
		prefix := r.paint("blue", marker)
		if lines[index] == "" {
			framed = append(framed, prefix)
			continue
		}
		framed = append(framed, prefix+" "+lines[index])
	}
	closing := r.paint("blue", r.anchor()) + " " + r.paint("bold", "PROLEWATCH") +
		r.paint("muted", r.divider()+"PACKAGE REVIEW ENDED"+r.divider()) + packagePhase
	if handoff {
		closing += r.paint("muted", r.divider()+phaseHandoff(phase))
	}
	framed = append(framed, closing)
	return strings.Join(framed, "\n")
}

// yayPackageContext finds this package's entry in the transaction yay
// described. Split packages produce several entries; the one named after the
// package base is the recipe being built.
func yayPackageContext(report *Report) (brief.YayPackageContext, bool) {
	if report == nil {
		return brief.YayPackageContext{}, false
	}
	for _, entry := range report.YayContext.Packages {
		if entry.Name == report.PackageBase {
			return entry, true
		}
	}
	if len(report.YayContext.Packages) == 1 {
		return report.YayContext.Packages[0], true
	}
	return brief.YayPackageContext{}, false
}

// packageTransition is the line a person actually decides on: which version is
// replacing which, why it is being installed at all, and whether its source
// moves under it.
//
// The hook has carried this since the beginning and the terminal never printed
// it. "foo / post, 3 sources - github.com (x2)" describes the tool's own
// phases; "1.2.3 -> 1.3.0, explicitly installed" describes the change the user
// is being asked about, and the same finding reads differently under each.
func packageTransition(report *Report, arrow, divider string) string {
	entry, ok := yayPackageContext(report)
	if !ok {
		return ""
	}
	version := terminalInline(entry.Version, 256)
	parts := []string{}
	switch {
	case entry.Upgrade && entry.LocalVersion != "" && version != "":
		parts = append(parts, terminalInline(entry.LocalVersion, 256)+" "+arrow+" "+version)
	case version != "":
		parts = append(parts, "new install "+version)
	}
	switch entry.Reason {
	case "explicit":
		parts = append(parts, "explicitly installed")
	case "dependency":
		parts = append(parts, "pulled in as a dependency")
	case "make_dependency":
		parts = append(parts, "pulled in as a make dependency")
	case "check_dependency":
		parts = append(parts, "pulled in as a check dependency")
	}
	if entry.Devel {
		parts = append(parts, "devel package: its upstream moves between builds")
	}
	return strings.Join(parts, divider)
}

// controlFileRank orders changed paths so the ones that decide what executes
// come first. A user reading four names out of two hundred should get the
// recipe and the scriptlet, not the first two alphabetically.
func controlFileRank(path string) int {
	base := strings.ToLower(path)
	if index := strings.LastIndex(base, "/"); index >= 0 {
		base = base[index+1:]
	}
	switch {
	case base == "pkgbuild" || base == ".srcinfo":
		return 0
	case strings.HasSuffix(base, ".install") || strings.HasSuffix(base, ".hook"):
		return 1
	case strings.HasSuffix(base, ".sh") || strings.HasSuffix(base, ".patch") || strings.HasSuffix(base, ".diff") || strings.HasSuffix(base, ".service"):
		return 2
	}
	return 3
}

// changedMaterial names what is different since the previous scan of this
// package, which is the question an upgrade actually raises.
//
// The wording says "the previous scan" rather than "the previous version"
// because the comparison is against the last report for this package and
// phase: across transactions for a fresh checkout, and within one transaction
// for the rescan after sources are unpacked. Both are worth seeing; claiming
// either is the other would be wrong half the time.
func changedMaterial(report *Report, divider string, shown int) string {
	if report == nil || len(report.ManifestDiff) == 0 {
		return ""
	}
	counts := map[string]int{}
	ranked := append([]brief.ManifestChange(nil), report.ManifestDiff...)
	for _, change := range report.ManifestDiff {
		counts[change.Status]++
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		return controlFileRank(ranked[i].Path) < controlFileRank(ranked[j].Path)
	})
	names := make([]string, 0, shown)
	for _, change := range ranked {
		if len(names) == shown {
			break
		}
		names = append(names, terminalInline(change.Path, 4096))
	}
	summary := make([]string, 0, 3)
	for _, status := range []string{"changed", "added", "deleted"} {
		if counts[status] > 0 {
			summary = append(summary, fmt.Sprintf("%d %s", counts[status], status))
		}
	}
	listing := strings.Join(names, ", ")
	if remaining := len(ranked) - len(names); remaining > 0 {
		listing += fmt.Sprintf(", and %d more", remaining)
	}
	return strings.Join(summary, ", ") + " since the previous scan" + divider + listing
}

// phaseResult renders a phase at the size that phase earned.
//
// One ordinary package produced four full briefings: the hook's pre scan, the
// hook's post-download scan, the wrapper's rescan after prepare, and the
// artifact review. Three of them said "NO BLOCKING FINDINGS" about a package
// nobody had a question about. Those are the tool's internal phase boundaries,
// which are real and worth having, and which the user never asked to read four
// times.
//
// So a phase that found nothing, needs no answer, and is not the last word
// before installation collapses to one line - carrying the part a person
// actually wanted, which is what is being installed and what changed. The
// artifact phase always renders in full: it is the briefing shown immediately
// before `pacman` gets the archive, and that is the moment to be complete.
func (r terminalRenderer) phaseResult(report *Report, status int, promptFollows, handoff bool) string {
	if !uneventful(report, status) {
		return r.reportWithHandoff(report, promptFollows, handoff)
	}
	return r.compactReport(report, handoff)
}

// uneventful reports whether a phase has nothing a person needs to read.
//
// A degraded phase still collapses, but never silently: compactReport carries
// the degradation on its one line. The reason is that the common degradation is
// persistent, not transient - the policy fingerprint the provider attestation
// is bound to includes bsdtar's digest and the provider CLI's version, so an
// ordinary `pacman -Syu` disables AI review until doctor is re-run. Refusing to
// collapse those phases meant a ten-package transaction printed thirty full
// blocks saying the same thing, which is how a warning becomes wallpaper. The
// artifact gate never collapses, so the full reason is still stated once per
// package, immediately before pacman receives the archive.
func uneventful(report *Report, status int) bool {
	return report != nil && status == 0 && len(report.Findings) == 0 &&
		!report.Overridden && report.CarriedDecision == nil && report.Phase != "artifact" && report.Decision == "allow"
}

func (r terminalRenderer) compactReport(report *Report, handoff bool) string {
	context := packageTransition(report, r.glyph("→", "->"), ", ")
	if changed := changedMaterial(report, ": ", 2); changed != "" {
		if context != "" {
			context += r.divider()
		}
		context += changed
	}
	if context == "" {
		context = "nothing to decide"
	}
	// A collapsed phase still says a configured scan did not run. Short, because
	// this line's whole purpose is being one line, and because the artifact gate
	// renders in full and carries the reason.
	degraded := ""
	if report.Reviewer.Error != "" {
		degraded = "AI review off · run 'prolewatch doctor'"
	}
	name := terminalInline(report.PackageBase, 4096)
	if !r.enabled() {
		line := fmt.Sprintf("%s / %s: no blocking findings; %s; report %s",
			name, terminalInline(report.Phase, 100), context, terminalInline(report.ReportID, 4096))
		if degraded != "" {
			line += "; AI review off, run 'prolewatch doctor'"
		}
		return line
	}
	prefix := r.paint("green", r.bullet()) + " "
	if handoff {
		prefix = r.paint("blue", r.anchor()) + " " + r.paint("bold", "PROLEWATCH") +
			r.paint("muted", r.divider()+"PHASE COMPLETE"+r.divider())
	}
	result := prefix + r.paint("bold", name) +
		r.paint("muted", " · "+phaseName(report.Phase)) + "  " + context
	if degraded != "" {
		result += r.paint("amber", r.divider()+degraded)
	}
	result += r.paint("muted", r.divider()+terminalInline(report.ReportID, 4096))
	if handoff {
		result += r.paint("muted", r.divider()+phaseHandoff(report.Phase))
	}
	return result
}

// aiReviewStatus makes a successful no-finding review visible. AI findings
// already appear in the Findings section, but without this line a clean run is
// indistinguishable from a skipped review unless the user decodes the dim
// provenance footer.
func aiReviewStatus(report *Report, divider string) (string, string) {
	if report == nil || report.Reviewer.Mode != ReviewModeAI {
		return "", ""
	}
	identity := terminalInline(report.Reviewer.Provider, 100)
	if model := terminalInline(report.Reviewer.Model, 256); model != "" {
		if identity != "" {
			identity += "/"
		}
		identity += model
	}
	if report.Reviewer.Error != "" {
		// "unavailable" alone does not distinguish a provider outage from an
		// attestation that went stale during a routine upgrade, and the second
		// is the common case. Carry the cause and the remedy here rather than
		// leaving them to the summary line.
		// "disabled for this run" rather than "not run": the muted, legitimate
		// case below already says "not run" when a structural finding stopped
		// the phase, and these two must not read alike. Prominence comes from
		// the DEGRADED stamp and the amber anchor, not from shouting in a line
		// whose every other status is lower case.
		parts := []string{"disabled for this run"}
		if identity != "" {
			parts = append(parts, identity)
		}
		if cause := strings.TrimSpace(strings.SplitN(report.Reviewer.Error, ";", 2)[0]); cause != "" {
			parts = append(parts, terminalInline(cause, 200))
		}
		parts = append(parts, "deterministic findings only", "run 'prolewatch doctor'")
		return strings.Join(parts, divider), "amber"
	}
	if len(report.Reviewer.Verdicts) == 0 {
		if report.Reviewer.Skipped != "" {
			// Muted, and never the DEGRADED stamp: nothing failed here.
			return strings.Join([]string{"not run", terminalInline(report.Reviewer.Skipped, 300)}, divider), "muted"
		}
		if report.Overridden {
			return strings.Join([]string{"not repeated", "exact one-time approval applied"}, divider), "muted"
		}
		return strings.Join([]string{"not run", "structural finding already stopped this phase"}, divider), "muted"
	}

	parts := []string{"completed"}
	if report.Reviewer.Trigger == reviewTriggerDecisionFindings {
		parts = append(parts, "triggered by findings")
	}
	if identity != "" {
		parts = append(parts, identity)
	}
	batches := len(report.Reviewer.Verdicts)
	batchLabel := "batches"
	if batches == 1 {
		batchLabel = "batch"
	}
	parts = append(parts, fmt.Sprintf("%d %s", batches, batchLabel))
	if guided := reportGuidanceCount(report); guided == 1 {
		parts = append(parts, "guidance for 1 finding")
	} else if guided > 1 {
		parts = append(parts, fmt.Sprintf("guidance for %d findings", guided))
	}

	aiFindings := 0
	aiFindingRole := "green"
	for _, finding := range report.Findings {
		if finding.Source == "ai" {
			aiFindings++
			if finding.Severity == "critical" || finding.Severity == "high" {
				aiFindingRole = "red"
			} else if aiFindingRole == "green" {
				aiFindingRole = "amber"
			}
		}
	}
	statusRole := "green"
	switch {
	case reportHasPromptInjection(report):
		parts = append(parts, "prompt injection reported")
		statusRole = "red"
	case verdictsHaveCoverageNotes(report.Reviewer.Verdicts):
		parts = append(parts, "coverage gaps reported")
		statusRole = "amber"
	case verdictsRequestDecision(report.Reviewer.Verdicts):
		parts = append(parts, "review requested a decision")
		statusRole = "amber"
	case aiFindings == 0:
		parts = append(parts, "no additional findings")
	case aiFindings == 1:
		parts = append(parts, "1 additional finding")
		statusRole = aiFindingRole
	default:
		parts = append(parts, fmt.Sprintf("%d additional findings", aiFindings))
		statusRole = aiFindingRole
	}
	if lowest := lowestVerdictConfidence(report.Reviewer.Verdicts); lowest != "" {
		parts = append(parts, "confidence "+terminalInline(lowest, 20))
	}
	return strings.Join(parts, divider), statusRole
}

func reportGuidanceCount(report *Report) int {
	if report == nil {
		return 0
	}
	targets := map[string]bool{}
	carried := carriedFindingIDSet(report.CarriedDecision)
	for _, finding := range report.Findings {
		if finding.Source == "deterministic" && !carried[findingGuidanceID(finding)] {
			targets[findingGuidanceID(finding)] = true
		}
	}
	seen := map[string]bool{}
	for _, verdict := range report.Reviewer.Verdicts {
		for _, guidance := range verdict.Guidance {
			if targets[guidance.FindingID] {
				seen[guidance.FindingID] = true
			}
		}
	}
	return len(seen)
}

// aiReviewScopeNote explains what the model could actually see at the recipe
// gate.
//
// Two files and no findings reads as "the AI is useless" unless you know the
// sources have not been fetched yet. Only the recipe gate gets this: it is the
// one whose scope is surprising, and it is opt-in, so the line exists only for
// people who asked for that gate.
func aiReviewScopeNote(report *Report) string {
	if report == nil || report.Phase != "pre" || len(report.Reviewer.Verdicts) == 0 {
		return ""
	}
	files := "files"
	if report.Coverage.SelectedFiles == 1 {
		files = "file"
	}
	return fmt.Sprintf("saw the recipe only: %d %s. Upstream sources are reviewed at the next gate.",
		report.Coverage.SelectedFiles, files)
}

func verdictsRequestDecision(verdicts []Verdict) bool {
	for _, verdict := range verdicts {
		if verdict.Verdict != "allow" {
			return true
		}
	}
	return false
}

// containmentSummary states what the build could reach, in the terms a user
// needs to calibrate alarm. Tense is load-bearing: "post" is the rescan after
// source retrieval and *before* the build, so only the artifact phase may speak
// in the past.
func containmentSummary(report *Report, divider string) string {
	stage := "upcoming build"
	if report != nil && report.Phase == "artifact" {
		stage = "build completed"
	}
	return strings.Join([]string{stage, "temporary empty home", "host identity hidden", "network prompts before contact"}, divider)
}

// sourceBriefing summarises where a package's material comes from: the count,
// and the distinct hosts. It is the first thing a user needs in order to judge
// the findings below it, and it is the line the architecture document's example
// briefing opens with.
// sourceHost names where one declared source comes from. A source with no
// parsable host is a file already in the checkout, which is worth distinguishing
// from a network fetch in the one line the user reads first.
func sourceHost(source brief.SourceProvenance) string {
	raw := source.URL
	if raw == "" {
		return "local"
	}
	for _, scheme := range []string{"git+", "hg+", "svn+", "bzr+", "fossil+"} {
		raw = strings.TrimPrefix(raw, scheme)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return "local"
	}
	return strings.ToLower(parsed.Hostname())
}

func sourceBriefing(report *Report) string {
	if report == nil || len(report.Sources) == 0 {
		return ""
	}
	counts := map[string]int{}
	var order []string
	for _, source := range report.Sources {
		host := sourceHost(source)
		if counts[host] == 0 {
			order = append(order, host)
		}
		counts[host]++
	}
	parts := make([]string, 0, len(order))
	for _, host := range order {
		part := terminalInline(host, 253)
		if counts[host] > 1 {
			part += fmt.Sprintf(" (x%d)", counts[host])
		}
		parts = append(parts, part)
	}
	return fmt.Sprintf("%d source(s)%s%s", len(report.Sources), " - ", strings.Join(parts, ", "))
}

func (r terminalRenderer) inlineDecisionResult(mode string, report *Report) string {
	if report == nil {
		return ""
	}
	if !report.Overridden {
		return r.report(report)
	}
	label, detail := "APPROVAL ACCEPTED", "exact one-time confidence approval"
	if mode == inlineOverride {
		label, detail = "OVERRIDE ACCEPTED", "exact one-time user override"
	}
	packagePhase := terminalInline(report.PackageBase, 4096) + " / " + terminalInline(report.Phase, 100)
	if !r.enabled() {
		return label + ": " + packagePhase + "; " + detail + "; report " + terminalInline(report.ReportID, 4096) + "\n"
	}
	lines := []string{
		r.paint("green", r.anchor()) + " " + r.paint("bold", label) + r.paint("muted", r.divider()) + r.paint("bold", packagePhase) + "  " + r.stamp("APPROVED BY YOU", "green"),
		r.paint("muted", r.branch()) + " " + detail + r.divider() + "report " + terminalInline(report.ReportID, 4096),
	}
	return strings.Join(lines, "\n") + "\n"
}

func (r terminalRenderer) checks(checks []Check) string {
	if !r.enabled() {
		return RenderChecks(checks)
	}
	ready := DoctorOK(checks)
	label, role := "BLOCK", "red"
	if ready {
		label, role = "READY", "green"
	}
	lines := []string{r.paint("blue", r.anchor()) + " " + r.paint("bold", "SYSTEM CHECK") + "  " + r.stamp(label, role)}
	for _, check := range checks {
		lines = append(lines, r.checkLine(check))
	}
	return strings.Join(lines, "\n")
}

// checkLine renders one check. Split out of checks so the same line can be
// printed as the check completes rather than only in the final block.
func (r terminalRenderer) checkLine(check Check) string {
	if !r.enabled() {
		// Not RenderChecks: that appends the closing summary line, which is a
		// property of the whole set and not of one check.
		return plainCheckLine(check)
	}
	checkLabel, checkRole, marker := "FAIL", "red", r.anchor()
	if check.OK {
		checkLabel, checkRole, marker = "OK", "green", r.bullet()
	} else if !check.Required {
		checkLabel, checkRole = "WARN", "amber"
	}
	line := r.paint(checkRole, marker+" ["+checkLabel+"]") + " " + terminalInline(check.Name, 200)
	if check.Detail != "" {
		line += r.paint("muted", r.divider()) + terminalInline(check.Detail, 2000)
	}
	return line
}

// checkActionLine precedes a slow doctor check with a durable status line. It
// deliberately does not masquerade as a Check: only the later OK/FAIL line is
// part of the machine-readable result and verdict.
func (r terminalRenderer) checkActionLine(name, detail string) string {
	if !r.enabled() {
		return fmt.Sprintf("[RUN] %s: %s", terminalInline(name, 200), terminalInline(detail, 2000))
	}
	line := r.paint("amber", r.bullet()+" [RUN]") + " " + terminalInline(name, 200)
	if detail != "" {
		line += r.paint("muted", r.divider()) + terminalInline(detail, 2000)
	}
	return line
}

// checksHeading opens the streamed form, where the verdict cannot be in the
// header because no check has run yet.
func (r terminalRenderer) checksHeading() string {
	return r.paint("blue", r.anchor()) + " " + r.paint("bold", "SYSTEM CHECK")
}

// checksVerdict closes the streamed form with the stamp the batch form carries
// in its header.
func (r terminalRenderer) checksVerdict(checks []Check) string {
	label, role := "BLOCK", "red"
	if DoctorOK(checks) {
		label, role = "READY", "green"
	}
	return r.paint("blue", r.anchor()) + " " + r.paint("bold", "RESULT") + "  " + r.stamp(label, role)
}

// findingOrigin names the pass a finding came from.
//
// Derived rather than read: only four of the finding constructors set Source at
// all, and policy.go's "ai" is the only one that carries information - the 52
// deterministic sites leave it empty. Testing for "ai" is therefore the honest
// test, and it keeps a new deterministic finding correctly labelled without
// having to remember the field.
func findingOrigin(finding brief.Finding) string {
	if finding.Source == "ai" {
		return "AI"
	}
	return "deterministic"
}

func humanBytes(value int64) string {
	// Use binary IEC units: every step is 1024 bytes, hence KiB/MiB rather than
	// decimal kB/MB. One decimal is useful only below ten units.
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	scaled := float64(value)
	unit := 0
	for scaled >= 1024 && unit+1 < len(units) {
		scaled /= 1024
		unit++
	}
	if unit == 0 {
		return strconv.FormatInt(value, 10) + " B"
	}
	name := units[unit]
	if scaled >= 10 {
		return fmt.Sprintf("%.0f %s", scaled, name)
	}
	return fmt.Sprintf("%.1f %s", scaled, name)
}

type terminalProgress struct {
	mu            sync.Mutex
	renderer      terminalRenderer
	package_      string
	phase         string
	stage         string
	batch         int
	batches       int
	reviewTrigger string
	deadline      time.Time
	stageAt       time.Time
	scan          brief.ScanProgress
	command       string
	activity      string
	sourceName    string
	sourcePart    int
	sourceAll     int
	sourceRead    int64
	sourceSize    int64
	sourceRate    int64
	sourceDone    bool
	stdoutTail    string
	stderrTail    string
	offline       bool
	networkSet    bool
	prefetched    bool
	longHint      bool
	now           func() time.Time
	lastDraw      time.Time
	lastLine      string
	stop          chan struct{}
	done          chan struct{}
	closed        bool
	suspended     bool
	dirty         bool
	liveLine      bool
}

// A live status owns only the terminal's current physical line. Carriage
// return plus EL2 can refresh that line without moving upward through yay's
// scrollback. terminalFitLine keeps it from wrapping onto a second row.
const terminalLiveLineClear = "\r\x1b[2K"

func newTerminalProgress(renderer terminalRenderer, packageBase, phase string) *terminalProgress {
	if !renderer.enabled() {
		return nil
	}
	p := &terminalProgress{renderer: renderer, package_: terminalInline(packageBase, 4096), phase: terminalInline(phase, 100), stage: StageInitializing, now: time.Now, stop: make(chan struct{}), done: make(chan struct{}), dirty: true}
	p.stageAt = p.now()
	p.draw(true)
	go p.loop()
	return p
}

func (p *terminalProgress) loop() {
	// Package scans and compiler output can update many times per second. Refresh
	// the current status line at most once per second rather than filling
	// scrollback with snapshots.
	ticker := time.NewTicker(time.Second)
	defer func() { ticker.Stop(); close(p.done) }()
	for {
		select {
		case <-ticker.C:
			p.draw(false)
		case <-p.stop:
			return
		}
	}
}

func (p *terminalProgress) draw(force bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.suspended {
		return
	}
	now := p.now()
	if !force && !p.lastDraw.IsZero() && now.Sub(p.lastDraw) < time.Second {
		return
	}
	// After 15 seconds, explain an intentionally quiet offline build once. This
	// reduces pressure to weaken network policy merely because compilation is slow.
	if p.stage == StageSandboxExecution && p.offline && !p.longHint && !p.stageAt.IsZero() && now.Sub(p.stageAt) >= 15*time.Second {
		detail := "still running · sandbox is offline · grant network only after a concrete fetch failure"
		if p.prefetched {
			detail = "still running · sandbox is offline by policy · locked dependencies were prefetched; compilation can take a while"
		}
		p.clearLineLocked()
		fmt.Fprintln(p.renderer.out, p.renderer.detailLine(detail))
		p.longHint = true
	}
	// An active deadline is itself changing measured state. Refresh it even when
	// the wrapped command is quiet, otherwise an unchanged countdown looks like
	// a hung build immediately after an interactive prompt.
	if !force && !p.dirty && p.deadline.IsZero() {
		return
	}
	line := p.lineLocked(now)
	if line == p.lastLine {
		p.dirty = false
		return
	}
	line = terminalFitLine(line, p.renderer.caps.Columns)
	_, _ = io.WriteString(p.renderer.out, terminalLiveLineClear+line)
	p.liveLine = true
	p.lastDraw, p.lastLine = now, line
	p.dirty = false
}

func (p *terminalProgress) clearLineLocked() {
	if !p.liveLine {
		return
	}
	_, _ = io.WriteString(p.renderer.out, terminalLiveLineClear)
	p.liveLine = false
	p.lastLine = ""
}

func terminalFitLine(value string, columns int) string {
	// Leave the final column unused: writing into it can trigger an automatic
	// wrap before the next carriage return on common terminals.
	limit := columns - 1
	if columns <= 1 || terminalDisplayCells(value) <= limit {
		return value
	}
	target := limit - 1
	if target < 0 {
		return ""
	}
	var output strings.Builder
	visible := 0
	for offset := 0; offset < len(value); {
		if end := terminalCSIEnd(value, offset); end > offset {
			output.WriteString(value[offset:end])
			offset = end
			continue
		}
		r, size := utf8.DecodeRuneInString(value[offset:])
		width := terminalRuneCells(r)
		if visible+width > target {
			break
		}
		output.WriteString(value[offset : offset+size])
		visible += width
		offset += size
	}
	output.WriteString("…")
	if strings.Contains(value, "\x1b[") {
		output.WriteString("\x1b[0m")
	}
	return output.String()
}

func terminalDisplayCells(value string) int {
	cells := 0
	for offset := 0; offset < len(value); {
		if end := terminalCSIEnd(value, offset); end > offset {
			offset = end
			continue
		}
		r, size := utf8.DecodeRuneInString(value[offset:])
		cells += terminalRuneCells(r)
		offset += size
	}
	return cells
}

func terminalCSIEnd(value string, offset int) int {
	if offset+2 > len(value) || value[offset] != '\x1b' || value[offset+1] != '[' {
		return offset
	}
	for index := offset + 2; index < len(value); index++ {
		if value[index] >= 0x40 && value[index] <= 0x7e {
			return index + 1
		}
	}
	return offset
}

func terminalRuneCells(r rune) int {
	if r == 0 || r < 0x20 || r == 0x7f || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r) {
		return 0
	}
	// The ranges below cover the wide/full-width characters relevant to file
	// names and status text without adding a terminal-width dependency.
	if r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
		(r >= 0xac00 && r <= 0xd7a3) || (r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe10 && r <= 0xfe19) || (r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff00 && r <= 0xff60) || (r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1faff) || (r >= 0x20000 && r <= 0x3fffd)) {
		return 2
	}
	return 1
}

// stageLabel renders a stage constant for the progress line.
//
// Only the acronym is corrected, not the case of the whole label. The line's
// other fragments - "batch 1/3", "running 5s", "offline" - are lower case, so
// title-casing the stage alone would single it out from its own line. "ai
// review" was simply wrong rather than merely lower case.
func stageLabel(stage string) string {
	words := strings.Split(strings.ReplaceAll(stage, "-", " "), " ")
	for i, word := range words {
		if word == "ai" {
			words[i] = "AI"
		}
	}
	return strings.Join(words, " ")
}

func (p *terminalProgress) lineLocked(now time.Time) string {
	stage := stageLabel(p.stage)
	if p.stage == StageAIReview && p.reviewTrigger == reviewTriggerDecisionFindings {
		stage += " (triggered by findings)"
	}
	parts := []string{p.renderer.paint("amber", p.renderer.bullet()) + " " + p.renderer.paint("bold", "GUARD")}
	if p.package_ != "" {
		label := p.package_
		if p.phase != "" {
			label += "/" + p.phase
		}
		parts = append(parts, label)
	}
	parts = append(parts, stage)
	if p.stage == StageAIReview && p.batches > 0 {
		parts = append(parts, fmt.Sprintf("batch %d/%d", p.batch, p.batches))
	}
	if p.stage == StageSandboxExecution {
		if !p.stageAt.IsZero() {
			if elapsed := now.Sub(p.stageAt).Truncate(time.Second); elapsed >= time.Second {
				parts = append(parts, "running "+elapsed.String())
			}
		}
		if p.networkSet && p.offline {
			parts = append(parts, "offline")
		}
	}
	if p.stage == StageSandboxExecution && p.command != "" {
		if p.activity != "" {
			parts = append(parts, "live "+p.activity)
		} else {
			parts = append(parts, "command "+p.command)
		}
	}
	if p.stage == StageSourceAcquisition && p.sourceName != "" {
		if p.sourceAll > 0 {
			parts = append(parts, fmt.Sprintf("source %d/%d", p.sourcePart, p.sourceAll))
		}
		parts = append(parts, p.sourceName)
		transferred := humanBytes(p.sourceRead)
		if p.sourceSize > 0 {
			transferred += " / " + humanBytes(p.sourceSize)
			if p.sourceRead <= p.sourceSize {
				transferred += fmt.Sprintf(" (%d%%)", p.sourceRead*100/p.sourceSize)
			}
		}
		parts = append(parts, transferred)
		if p.sourceRate > 0 {
			parts = append(parts, humanBytes(p.sourceRate)+"/s")
		}
		if p.sourceDone {
			parts = append(parts, "downloaded")
		}
	}
	if p.scan.FilesSeen > 0 {
		parts = append(parts, fmt.Sprintf("%d files", p.scan.FilesSeen))
	}
	if p.scan.BytesSeen > 0 {
		parts = append(parts, humanBytes(p.scan.BytesSeen)+" input")
	}
	if p.scan.ArchivesSeen > 0 {
		parts = append(parts, fmt.Sprintf("%d archives", p.scan.ArchivesSeen))
	}
	if p.scan.ArchiveEntries > 0 {
		parts = append(parts, fmt.Sprintf("%d entries", p.scan.ArchiveEntries))
	}
	if p.scan.ArchiveUnpackedBytes > 0 {
		parts = append(parts, humanBytes(p.scan.ArchiveUnpackedBytes)+" unpacked")
	}
	if !p.deadline.IsZero() {
		remaining := p.deadline.Sub(now)
		if remaining <= 0 {
			parts = append(parts, p.renderer.paint("red", "deadline reached"))
		} else {
			parts = append(parts, "deadline "+remaining.Round(time.Second).String())
		}
	}
	return strings.Join(parts, p.renderer.paint("muted", p.renderer.divider()))
}

func (p *terminalProgress) Stage(stage string, timeoutSeconds int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.stage, p.batch, p.batches, p.reviewTrigger = terminalInline(stage, 100), 0, 0, ""
	p.stageAt, p.longHint = p.now(), false
	p.activity, p.stdoutTail, p.stderrTail = "", "", ""
	p.sourceName, p.sourcePart, p.sourceAll = "", 0, 0
	p.sourceRead, p.sourceSize, p.sourceRate, p.sourceDone = 0, 0, 0, false
	p.suspended = false
	p.dirty = true
	p.deadline = time.Time{}
	if timeoutSeconds > 0 {
		p.deadline = p.now().Add(time.Duration(timeoutSeconds) * time.Second)
	}
	p.mu.Unlock()
	p.draw(true)
}

func (p *terminalProgress) AI(batch, batches, timeoutSeconds int, trigger string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.stage, p.batch, p.batches, p.reviewTrigger = StageAIReview, batch, batches, terminalInline(trigger, 100)
	p.dirty = true
	p.deadline = time.Time{}
	if timeoutSeconds > 0 {
		p.deadline = p.now().Add(time.Duration(timeoutSeconds) * time.Second)
	}
	p.mu.Unlock()
	p.draw(true)
}

func (p *terminalProgress) Scan(progress brief.ScanProgress) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.scan = progress
	p.dirty = true
	p.mu.Unlock()
	p.draw(false)
}

func (p *terminalProgress) SetPackage(packageBase string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.package_ = terminalInline(packageBase, 4096)
	p.dirty = true
	p.mu.Unlock()
	p.draw(true)
}

func (p *terminalProgress) SetCommand(command string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.command = terminalInline(command, 320)
	p.dirty = true
	p.mu.Unlock()
	p.draw(false)
}

func (p *terminalProgress) SetActivity(activity string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.activity = terminalInline(activity, 320)
	p.dirty = true
	p.mu.Unlock()
	p.draw(true)
}

func (p *terminalProgress) Source(name string, part, all int, read, size, rate int64, complete bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	changedSource := p.sourceName != name || p.sourcePart != part
	p.sourceName = terminalInline(name, 512)
	p.sourcePart, p.sourceAll = part, all
	p.sourceRead, p.sourceSize, p.sourceRate, p.sourceDone = read, size, rate, complete
	p.dirty = true
	p.mu.Unlock()
	p.draw(changedSource || complete)
}

func (p *terminalProgress) ObserveOutput(stream commandOutputStream, value []byte) {
	if p == nil || len(value) == 0 {
		return
	}
	p.mu.Lock()
	carry := &p.stdoutTail
	if stream == commandStderr {
		carry = &p.stderrTail
	}
	*carry, p.activity = latestCommandOutputLine(*carry, value, p.activity)
	p.dirty = true
	p.mu.Unlock()
	p.draw(false)
}

func latestCommandOutputLine(carry string, value []byte, previous string) (string, string) {
	// Output callbacks may split UTF-8/text lines arbitrarily. Keep at most 4 KiB
	// of incomplete tail and expose a sanitized 140-character activity hint; the
	// full bounded stdout/stderr buffers remain the source for error reporting.
	const carryLimit = 4096
	combined := carry + strings.ReplaceAll(string(value), "\r", "\n")
	if len(combined) > carryLimit {
		combined = combined[len(combined)-carryLimit:]
	}
	lines := strings.Split(combined, "\n")
	nextCarry := lines[len(lines)-1]
	latest := ""
	for index := len(lines) - 2; index >= 0; index-- {
		if candidate := strings.TrimSpace(lines[index]); candidate != "" {
			latest = candidate
			break
		}
	}
	if latest == "" {
		latest = strings.TrimSpace(nextCarry)
	}
	if latest == "" {
		return nextCarry, previous
	}
	return nextCarry, terminalInline(latest, 140)
}

func (p *terminalProgress) SetNetwork(enabled, prefetched bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.offline = !enabled
	p.networkSet = true
	p.prefetched = !enabled && prefetched
	p.dirty = true
	p.mu.Unlock()
	p.draw(false)
}

func (p *terminalProgress) PrepareOutput() {
	// Reports and replayed package output start at column zero after removing the
	// live line. A later stage resumes progress with a fresh current-line status.
	if p == nil {
		return
	}
	p.mu.Lock()
	if !p.closed && !p.suspended {
		p.clearLineLocked()
		p.suspended = true
	}
	p.mu.Unlock()
}

func (p *terminalProgress) ResumeAfterPrompt() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.suspended = false
	p.dirty = true
	p.lastDraw = time.Time{}
	p.mu.Unlock()
	p.draw(true)
}

func (p *terminalProgress) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.clearLineLocked()
	p.closed = true
	close(p.stop)
	p.mu.Unlock()
	<-p.done
}

type terminalProgressContextKey struct{}

func withTerminalProgress(ctx context.Context, progress *terminalProgress) context.Context {
	if progress == nil {
		return ctx
	}
	return context.WithValue(ctx, terminalProgressContextKey{}, progress)
}

func terminalProgressFrom(ctx context.Context) *terminalProgress {
	if ctx == nil {
		return nil
	}
	progress, _ := ctx.Value(terminalProgressContextKey{}).(*terminalProgress)
	return progress
}

func prepareTerminalOutput(ctx context.Context) {
	if progress := terminalProgressFrom(ctx); progress != nil {
		progress.PrepareOutput()
	}
}
