package audit

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type terminalColorLevel int

const (
	terminalColorNone terminalColorLevel = iota
	terminalColor16
	terminalColor256
	terminalColorTrue
)

type terminalCapabilities struct {
	Interactive bool
	Unicode     bool
	Color       terminalColorLevel
}

type terminalRenderer struct {
	out                  io.Writer
	caps                 terminalCapabilities
	autoEnableKnownTools bool
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
	return p.renderer.paint("rust", p.renderer.anchor()) + " " + p.renderer.paint("bold", terminalInline(title, 200)) + "  " + p.renderer.stamp(terminalInline(stamp, 40), role)
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
		return terminalRenderer{out: out, autoEnableKnownTools: cfg.Network.AutoEnableKnownTools}
	}
	return terminalRenderer{out: out, caps: detectTerminalCapabilities(out, os.Getenv, os.LookupEnv), autoEnableKnownTools: cfg.Network.AutoEnableKnownTools}
}

func terminalRendererWithCapabilities(out io.Writer, caps terminalCapabilities) terminalRenderer {
	return terminalRenderer{out: out, caps: caps}
}

func detectTerminalCapabilities(out io.Writer, getenv func(string) string, lookupEnv func(string) (string, bool)) terminalCapabilities {
	file, ok := out.(*os.File)
	term := strings.ToLower(getenv("TERM"))
	if !ok || term == "" || term == "dumb" || !isTerminalFile(file) {
		return terminalCapabilities{}
	}
	return terminalEnvironmentCapabilities(getenv, lookupEnv)
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
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
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
			"red": "1;38;2;211;81;85", "rust": "38;2;163;43;48", "amber": "38;2;208;163;91",
			"green": "38;2;120;170;130", "muted": "38;2;170;162;154", "bold": "1",
		}[role]
	case terminalColor256:
		code = map[string]string{"red": "1;38;5;167", "rust": "38;5;124", "amber": "38;5;179", "green": "38;5;108", "muted": "38;5;145", "bold": "1"}[role]
	case terminalColor16:
		code = map[string]string{"red": "1;31", "rust": "31", "amber": "33", "green": "32", "muted": "2", "bold": "1"}[role]
	}
	if code == "" {
		return value
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func (r terminalRenderer) bullet() string { return r.glyph("•", "*") }
func (r terminalRenderer) anchor() string { return r.glyph("◆", "#") }
func (r terminalRenderer) branch() string { return r.glyph("└─", "\\-") }
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
	return r.paint("rust", r.anchor()) + " " + r.paint("bold", "PROLEWATCH ACTIVE") + r.paint("muted", r.divider()+"guarding this yay transaction")
}

func (r terminalRenderer) successLine(message string) string {
	if !r.enabled() {
		return message
	}
	return r.paint("green", r.bullet()) + " " + message + "  " + r.stamp("READY", "green")
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

func (r terminalRenderer) blockLine(message string) string {
	if !r.enabled() {
		return message
	}
	return r.paint("red", r.anchor()) + " " + message + "  " + r.stamp("BLOCK", "red")
}

func (r terminalRenderer) sealedLine(count int) string {
	if !r.enabled() {
		return ""
	}
	return r.paint("green", r.bullet()) + fmt.Sprintf(" %d reviewed artifact(s) moved into the sealed pool  ", count) + r.stamp("SEALED", "green")
}

func (r terminalRenderer) guardComplete(report *Report) string {
	if report == nil {
		return ""
	}
	packagePhase := terminalInline(report.PackageBase, 4096) + " / " + terminalInline(report.Phase, 100)
	if !r.enabled() {
		return "Guard complete: " + packagePhase + "; control returned to yay"
	}
	return r.paint("muted", r.branch()) + " " + r.paint("green", "guard complete") + r.paint("muted", r.divider()+packagePhase+r.divider()+"yay resumes")
}

func (r terminalRenderer) report(report *Report) string {
	if !r.enabled() {
		return RenderReport(report)
	}
	decision, role := "BLOCK", "red"
	if report.Decision == "allow" {
		decision, role = "ALLOW", "green"
	}
	if report.UnsafeBypass {
		decision, role = "BYPASS", "amber"
	}
	content := report.ContentHash
	if content == "" {
		content = "unavailable"
	}
	lines := []string{
		r.paint("rust", r.anchor()) + " " + r.paint("bold", "INSPECTION") + r.paint("muted", r.divider()) + r.paint("bold", terminalInline(report.PackageBase, 4096)) + r.paint("muted", " / "+terminalInline(report.Phase, 100)) + "  " + r.stamp(decision, role),
		r.paint("muted", r.bullet()) + " report   " + terminalInline(report.ReportID, 4096),
		r.paint("muted", r.bullet()) + " content  " + terminalInline(content, 128),
	}
	review := terminalInline(report.Reviewer.Mode, 100)
	if report.Reviewer.Mode == ReviewModeAI {
		review += r.divider() + terminalInline(report.Reviewer.Provider, 100) + " / " + terminalInline(report.Reviewer.Model, 256)
		if lowest := lowestVerdictConfidence(report.Reviewer.Verdicts); lowest != "" {
			review += r.divider() + "confidence " + terminalInline(lowest, 20)
		}
		review += r.divider() + "minimum " + terminalInline(report.Reviewer.MinimumConfidence, 20)
	}
	lines = append(lines, r.paint("muted", r.bullet())+" review   "+review)
	if sources := sourceSummary(report.Sources, report.SourceVerification); sources != "" {
		lines = append(lines, r.paint("muted", r.bullet())+" vendor   "+terminalInline(sources, 1000))
	}
	lines = append(lines, r.paint(role, r.branch())+" "+terminalInline(report.Summary, 4096))
	if verdictsHaveCoverageNotes(report.Reviewer.Verdicts) {
		lines = append(lines, "", r.paint("bold", "AI coverage gaps"))
		for batch, verdict := range report.Reviewer.Verdicts {
			for _, note := range verdict.CoverageNotes {
				lines = append(lines, "  "+r.paint("amber", r.anchor())+" batch "+strconv.Itoa(batch+1)+r.divider()+terminalInline(note, 1000))
			}
		}
	}
	if len(report.Findings) > 0 {
		lines = append(lines, "", r.paint("bold", "Findings")+r.paint("muted", r.divider()+"critical to info"))
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
			lines = append(lines, "  "+r.paint(findingRole, r.anchor()+" "+severity)+r.divider()+strings.ToUpper(terminalInline(item.Source, 20))+r.divider()+terminalInline(item.Category, 80)+r.divider()+location)
			lines = append(lines, "    "+r.paint("muted", r.branch())+" "+terminalInline(item.Rationale, 2000)+"; evidence="+terminalInline(item.Evidence, 320))
		}
	}
	selection := fmt.Sprintf("%d selected for AI review", report.Coverage.SelectedFiles)
	if report.Reviewer.Mode == ReviewModeDeterministicOnly {
		selection = "AI text selection disabled"
	}
	lines = append(lines, "", r.paint("muted", r.bullet())+fmt.Sprintf(" coverage %d files%s%s%s%s", report.Coverage.FilesSeen, r.divider(), humanBytes(report.Coverage.BytesSeen), r.divider(), selection))
	if report.Decision == "block" && report.ApprovalEligible {
		lines = append(lines, r.paint("amber", r.branch())+" override: prolewatch approve "+terminalInline(report.ReportID, 4096))
	}
	if report.Decision == "block" && report.UnsafeBypassEligible {
		lines = append(lines, r.paint("red", r.branch())+" unsafe bypass: available only through the interactive yay gate")
	}
	if report.NetworkEligible {
		steps := knownNetworkSteps(report, "")
		if r.autoEnableKnownTools && len(steps) > 0 {
			lines = append(lines, r.paint("amber", r.branch())+" network auto-detected"+r.divider()+terminalInline(strings.Join(steps, ", "), 1000)+r.divider()+"enabled only for its matching recipe-phase sandbox")
		} else {
			lines = append(lines, r.paint("amber", r.branch())+" network: prolewatch allow-network "+terminalInline(report.ReportID, 4096))
		}
	}
	return strings.Join(lines, "\n")
}

func (r terminalRenderer) inlineDecisionResult(mode string, report *Report) string {
	if report == nil {
		return ""
	}
	if !report.Overridden || mode == inlineBypass {
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
		r.paint("green", r.anchor()) + " " + r.paint("bold", label) + r.paint("muted", r.divider()) + r.paint("bold", packagePhase) + "  " + r.stamp("ALLOW", "green"),
		r.paint("muted", r.branch()) + " " + detail + r.divider() + "report " + terminalInline(report.ReportID, 4096),
	}
	return strings.Join(lines, "\n") + "\n"
}

func (r terminalRenderer) automaticNetwork(packageBase, phase string, steps []string) string {
	label := terminalInline(packageBase, 4096)
	if phase != "" {
		label += " / " + terminalInline(phase, 100)
	}
	step := strings.Join(steps, ", ")
	if !r.enabled() {
		return "Prolewatch build network automatically enabled for recognized recipe step(s): " + terminalInline(step, 1000)
	}
	return r.paint("amber", r.anchor()) + " " + r.paint("bold", "BUILD NETWORK") + r.paint("muted", r.divider()) + r.paint("bold", label) + "  " + r.stamp("AUTO", "amber") + "\n" +
		r.paint("muted", r.branch()) + " recognized recipe step" + r.divider() + terminalInline(step, 1000) + r.divider() + "bounded public HTTP(S) broker enabled for this makepkg invocation"
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
	lines := []string{r.paint("rust", r.anchor()) + " " + r.paint("bold", "SYSTEM CHECK") + "  " + r.stamp(label, role)}
	for _, check := range checks {
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
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func humanBytes(value int64) string {
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
	mu         sync.Mutex
	renderer   terminalRenderer
	package_   string
	phase      string
	stage      string
	batch      int
	batches    int
	deadline   time.Time
	stageAt    time.Time
	scan       ActivityScanProgress
	command    string
	activity   string
	stdoutTail string
	stderrTail string
	offline    bool
	prefetched bool
	longHint   bool
	now        func() time.Time
	lastDraw   time.Time
	lastLine   string
	frame      int
	stop       chan struct{}
	done       chan struct{}
	closed     bool
	suspended  bool
}

func newTerminalProgress(renderer terminalRenderer, packageBase, phase string) *terminalProgress {
	if !renderer.enabled() {
		return nil
	}
	p := &terminalProgress{renderer: renderer, package_: terminalInline(packageBase, 4096), phase: terminalInline(phase, 100), stage: StageInitializing, now: time.Now, stop: make(chan struct{}), done: make(chan struct{})}
	p.stageAt = p.now()
	p.draw(true)
	go p.loop()
	return p
}

func (p *terminalProgress) loop() {
	ticker := time.NewTicker(200 * time.Millisecond)
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
	if !force && !p.lastDraw.IsZero() && now.Sub(p.lastDraw) < 200*time.Millisecond {
		return
	}
	if !force {
		p.frame++
	}
	if p.stage == StageSandboxExecution && p.offline && !p.longHint && !p.stageAt.IsZero() && now.Sub(p.stageAt) >= 15*time.Second {
		fmt.Fprint(p.renderer.out, "\r\x1b[2K")
		detail := "still running · sandbox is offline · grant network only after a concrete fetch failure"
		if p.prefetched {
			detail = "still running · sandbox is offline by policy · locked dependencies were prefetched; compilation can take a while"
		}
		fmt.Fprintln(p.renderer.out, p.renderer.detailLine(detail))
		p.lastLine = ""
		p.longHint = true
	}
	line := p.lineLocked(now)
	if !force && line == p.lastLine {
		return
	}
	fmt.Fprint(p.renderer.out, "\r\x1b[2K", line)
	p.lastDraw, p.lastLine = now, line
}

func (p *terminalProgress) lineLocked(now time.Time) string {
	stage := strings.ReplaceAll(p.stage, "-", " ")
	unicodeFrames := []string{"◐", "◓", "◑", "◒"}
	asciiFrames := []string{"|", "/", "-", "\\"}
	frames := asciiFrames
	if p.renderer.caps.Unicode {
		frames = unicodeFrames
	}
	wheel := frames[p.frame%len(frames)]
	parts := []string{p.renderer.paint("amber", wheel), p.renderer.paint("bold", "GUARD")}
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
	if p.stage == StageSandboxExecution && p.command != "" {
		if p.activity != "" {
			parts = append(parts, "live "+p.activity)
		} else {
			parts = append(parts, "command "+p.command)
		}
	}
	if p.scan.FilesSeen > 0 {
		parts = append(parts, fmt.Sprintf("%d files", p.scan.FilesSeen))
	}
	if p.scan.BytesSeen > 0 {
		parts = append(parts, humanBytes(p.scan.BytesSeen))
	}
	if p.scan.ArchivesSeen > 0 {
		parts = append(parts, fmt.Sprintf("%d archives", p.scan.ArchivesSeen))
	}
	if p.scan.ArchiveEntries > 0 {
		parts = append(parts, fmt.Sprintf("%d entries", p.scan.ArchiveEntries))
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
	p.stage, p.batch, p.batches = terminalInline(stage, 100), 0, 0
	p.stageAt, p.longHint = p.now(), false
	p.activity, p.stdoutTail, p.stderrTail = "", "", ""
	p.suspended = false
	p.deadline = time.Time{}
	if timeoutSeconds > 0 {
		p.deadline = p.now().Add(time.Duration(timeoutSeconds) * time.Second)
	}
	p.mu.Unlock()
	p.draw(false)
}

func (p *terminalProgress) AI(batch, batches, timeoutSeconds int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.stage, p.batch, p.batches = StageAIReview, batch, batches
	p.deadline = time.Time{}
	if timeoutSeconds > 0 {
		p.deadline = p.now().Add(time.Duration(timeoutSeconds) * time.Second)
	}
	p.mu.Unlock()
	p.draw(false)
}

func (p *terminalProgress) Scan(progress ActivityScanProgress) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.scan = progress
	p.mu.Unlock()
	p.draw(false)
}

func (p *terminalProgress) SetPackage(packageBase string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.package_ = terminalInline(packageBase, 4096)
	p.mu.Unlock()
	p.draw(false)
}

func (p *terminalProgress) SetCommand(command string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.command = terminalInline(command, 320)
	p.mu.Unlock()
	p.draw(false)
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
	p.mu.Unlock()
	p.draw(false)
}

func latestCommandOutputLine(carry string, value []byte, previous string) (string, string) {
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
	p.prefetched = !enabled && prefetched
	p.mu.Unlock()
	p.draw(false)
}

func (p *terminalProgress) PrepareOutput() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if !p.closed && !p.suspended {
		p.suspended = true
		p.lastLine = ""
		fmt.Fprint(p.renderer.out, "\r\x1b[2K")
	}
	p.mu.Unlock()
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
	p.closed = true
	close(p.stop)
	if !p.suspended {
		fmt.Fprint(p.renderer.out, "\r\x1b[2K")
	}
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
