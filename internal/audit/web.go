package audit

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed webui/*
var webUI embed.FS

var webCleanRootIdentity = activeCleanRootIdentity
var webNow = time.Now

type webReportSummary struct {
	ReportID        string         `json:"report_id"`
	TransactionID   string         `json:"transaction_id"`
	CreatedAt       string         `json:"created_at"`
	PackageBase     string         `json:"package_base"`
	Phase           string         `json:"phase"`
	Decision        string         `json:"decision"`
	Disposition     string         `json:"disposition"`
	Summary         string         `json:"summary"`
	SeverityCounts  map[string]int `json:"severity_counts"`
	FindingCount    int            `json:"finding_count"`
	SandboxRunCount int            `json:"sandbox_run_count"`
}

type webActivity struct {
	ActivityID     string               `json:"activity_id"`
	TransactionID  string               `json:"transaction_id"`
	PackageBase    string               `json:"package_base,omitempty"`
	Kind           string               `json:"kind"`
	Phase          string               `json:"phase"`
	Stage          string               `json:"stage"`
	Status         string               `json:"status"`
	StartedAt      string               `json:"started_at"`
	UpdatedAt      string               `json:"updated_at"`
	FinishedAt     string               `json:"finished_at,omitempty"`
	StageStartedAt string               `json:"stage_started_at"`
	LastProgressAt string               `json:"last_progress_at"`
	DeadlineAt     string               `json:"deadline_at,omitempty"`
	AIBatch        int                  `json:"ai_batch,omitempty"`
	AIBatchCount   int                  `json:"ai_batch_count,omitempty"`
	ReportIDs      []string             `json:"report_ids"`
	Message        string               `json:"message,omitempty"`
	FailureReason  string               `json:"failure_reason,omitempty"`
	Health         string               `json:"health"`
	HealthMessage  string               `json:"health_message,omitempty"`
	ScanProgress   ActivityScanProgress `json:"scan_progress"`
	Containment    ActivityContainment  `json:"containment"`
}

type webCleanRoot struct {
	Status         string `json:"status"`
	Generation     string `json:"generation,omitempty"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
}

type webOverview struct {
	ApplicationVersion string             `json:"application_version"`
	GeneratedAt        string             `json:"generated_at"`
	CleanRoot          webCleanRoot       `json:"clean_root"`
	Activities         []webActivity      `json:"activities"`
	Reports            []webReportSummary `json:"reports"`
}

type webReportDetail struct {
	ReportID           string               `json:"report_id"`
	TransactionID      string               `json:"transaction_id"`
	CreatedAt          string               `json:"created_at"`
	PackageBase        string               `json:"package_base"`
	Phase              string               `json:"phase"`
	Decision           string               `json:"decision"`
	Disposition        string               `json:"disposition"`
	Summary            string               `json:"summary"`
	ContentHash        string               `json:"content_hash"`
	PolicyFingerprint  string               `json:"policy_fingerprint"`
	ApplicationVersion string               `json:"application_version"`
	Reviewer           ReviewerReport       `json:"reviewer"`
	Coverage           Coverage             `json:"coverage"`
	Exclusions         []string             `json:"exclusions"`
	Findings           []Finding            `json:"findings"`
	ManifestDiff       []ManifestChange     `json:"manifest_diff"`
	Overridden         bool                 `json:"overridden"`
	UnsafeBypass       bool                 `json:"unsafe_bypass"`
	ApprovalEligible   bool                 `json:"approval_eligible"`
	NetworkEligible    bool                 `json:"network_eligible"`
	SealedArtifacts    []SealedArtifact     `json:"sealed_artifacts"`
	SandboxRuns        []SandboxEnforcement `json:"sandbox_runs"`
	Sources            []SourceProvenance   `json:"sources"`
	SourceVerification SourceVerification   `json:"source_verification"`
}

type cachedWebSummary struct {
	modTime int64
	size    int64
	summary webReportSummary
}

type webServer struct {
	token      string
	host       string
	reports    *ReportStore
	activities *ActivityStore
	assets     http.Handler
	mu         sync.Mutex
	cache      map[string]cachedWebSummary
}

func runWeb(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("web", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	port := flags.Int("port", 0, "loopback TCP port (0 chooses an ephemeral port)")
	if err := flags.Parse(args); err != nil {
		return 20
	}
	if flags.NArg() != 0 || *port < 0 || *port > 65535 {
		return cliError(20, errors.New("web accepts only --port 0..65535"))
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(*port))
	if err != nil {
		return cliError(23, err)
	}
	defer listener.Close()
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return cliError(23, err)
	}
	host := listener.Addr().String()
	server, err := newWebServer(host, hex.EncodeToString(random))
	if err != nil {
		return cliError(23, err)
	}
	httpServer := &http.Server{
		Handler: server.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024,
	}
	done := make(chan error, 1)
	go func() { done <- httpServer.Serve(listener) }()
	fmt.Println(rendererFor(os.Stdout).successLine("Prolewatch dashboard: http://" + host + "/#token=" + server.token))
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdown); err != nil {
			return cliError(23, err)
		}
		return 0
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return 0
		}
		return cliError(23, err)
	}
}

func newWebServer(host, token string) (*webServer, error) {
	hostIP, _, err := net.SplitHostPort(host)
	parsedHost := net.ParseIP(hostIP)
	if err != nil || parsedHost == nil || !parsedHost.Equal(net.IPv4(127, 0, 0, 1)) || len(token) != 64 {
		return nil, errors.New("invalid web server identity")
	}
	assets, err := fs.Sub(webUI, "webui")
	if err != nil {
		return nil, err
	}
	return &webServer{token: token, host: host, reports: NewReportStore(), activities: NewActivityStore(), assets: http.FileServer(http.FS(assets)), cache: map[string]cachedWebSummary{}}, nil
}

func (s *webServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/overview", s.overview)
	mux.HandleFunc("/api/reports/", s.report)
	mux.Handle("/", s.assets)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		if request.Host != s.host || !loopbackRemote(request.RemoteAddr) {
			http.Error(writer, "forbidden", http.StatusForbidden)
			return
		}
		if strings.Contains(request.URL.Path, "/../") || strings.Contains(request.URL.Path, "/./") || request.URL.RawPath != "" {
			http.NotFound(writer, request)
			return
		}
		if request.URL.Path == "/" || request.URL.Path == "/app.css" || request.URL.Path == "/app.js" || request.URL.Path == "/logo.png" {
			if request.Method != http.MethodGet && request.Method != http.MethodHead {
				writer.Header().Set("Allow", "GET, HEAD")
				http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
		} else {
			if request.Method != http.MethodGet {
				writer.Header().Set("Allow", "GET")
				http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !s.authorized(request) {
				http.Error(writer, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		mux.ServeHTTP(writer, request)
	})
}

func loopbackRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	parsed := net.ParseIP(host)
	return err == nil && parsed != nil && parsed.Equal(net.IPv4(127, 0, 0, 1))
}

func (s *webServer) authorized(request *http.Request) bool {
	const prefix = "Bearer "
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	provided := strings.TrimPrefix(header, prefix)
	return len(provided) == len(s.token) && subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) == 1
}

func (s *webServer) overview(writer http.ResponseWriter, _ *http.Request) {
	now := webNow().UTC()
	activities, err := s.activities.List(100)
	if err != nil {
		http.Error(writer, "activity state unavailable", http.StatusInternalServerError)
		return
	}
	reports, err := s.reportSummaries(50)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		http.Error(writer, "report state unavailable", http.StatusInternalServerError)
		return
	}
	cleanRoot := webCleanRoot{Status: "unknown"}
	if identity, err := webCleanRootIdentity(); err == nil {
		cleanRoot.Status = "unavailable"
		if identity.Available {
			cleanRoot = webCleanRoot{Status: "available", Generation: identity.Generation, ManifestSHA256: identity.ManifestSHA256}
		}
	}
	webActivities := make([]webActivity, 0, len(activities))
	for _, activity := range activities {
		webActivities = append(webActivities, activityForWebAt(activity, now))
	}
	writeWebJSON(writer, webOverview{ApplicationVersion: ApplicationVersion, GeneratedAt: now.Format(time.RFC3339Nano), CleanRoot: cleanRoot, Activities: webActivities, Reports: reports})
}

func (s *webServer) report(writer http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/api/reports/")
	raw := strings.HasSuffix(path, "/raw")
	if raw {
		path = strings.TrimSuffix(path, "/raw")
	}
	if !reportIDRE.MatchString(path) || strings.Contains(path, "/") {
		http.NotFound(writer, request)
		return
	}
	report, err := s.reports.Load(path)
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	if raw {
		writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", report.ReportID+".json"))
		writeWebJSON(writer, report)
		return
	}
	detail := webReportDetail{ReportID: report.ReportID, TransactionID: webTransactionID(report.Transaction), CreatedAt: report.CreatedAt,
		PackageBase: report.PackageBase, Phase: report.Phase, Decision: report.Decision, Disposition: report.Disposition, Summary: report.Summary,
		ContentHash: report.ContentHash, PolicyFingerprint: report.PolicyFingerprint, ApplicationVersion: report.ApplicationVersion,
		Reviewer: report.Reviewer, Coverage: report.Coverage, Exclusions: webList(report.Exclusions), Findings: webList(report.Findings),
		ManifestDiff: webList(report.ManifestDiff), Overridden: report.Overridden, UnsafeBypass: report.UnsafeBypass, ApprovalEligible: report.ApprovalEligible,
		NetworkEligible: report.NetworkEligible, SealedArtifacts: webList(report.SealedArtifacts), SandboxRuns: webList(report.SandboxRuns),
		Sources: webList(report.Sources), SourceVerification: report.SourceVerification}
	writeWebJSON(writer, detail)
}

func (s *webServer) reportSummaries(limit int) ([]webReportSummary, error) {
	ids, err := s.reports.IDs(limit)
	if err != nil {
		return []webReportSummary{}, err
	}
	result := make([]webReportSummary, 0, len(ids))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		path := filepath.Join(s.reports.Root, id+".json")
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		cached, ok := s.cache[id]
		if !ok || cached.modTime != info.ModTime().UnixNano() || cached.size != info.Size() {
			report, err := s.reports.Load(id)
			if err != nil {
				continue
			}
			cached = cachedWebSummary{modTime: info.ModTime().UnixNano(), size: info.Size(), summary: summarizeReport(report)}
			s.cache[id] = cached
		}
		result = append(result, cached.summary)
	}
	return result, nil
}

func summarizeReport(report *Report) webReportSummary {
	counts := map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
	for _, finding := range report.Findings {
		counts[finding.Severity]++
	}
	return webReportSummary{ReportID: report.ReportID, TransactionID: webTransactionID(report.Transaction), CreatedAt: report.CreatedAt,
		PackageBase: report.PackageBase, Phase: report.Phase, Decision: report.Decision, Disposition: report.Disposition, Summary: report.Summary,
		SeverityCounts: counts, FindingCount: len(report.Findings), SandboxRunCount: len(report.SandboxRuns)}
}

func activityForWeb(activity Activity) webActivity {
	return activityForWebAt(activity, webNow().UTC())
}

func activityForWebAt(activity Activity, now time.Time) webActivity {
	health, healthMessage := activityHealth(activity, now)
	return webActivity{ActivityID: activity.ActivityID, TransactionID: webTransactionID(activity.Transaction), PackageBase: activity.PackageBase,
		Kind: activity.Kind, Phase: activity.Phase, Stage: activity.Stage, Status: activity.Status, StartedAt: activity.StartedAt,
		UpdatedAt: activity.UpdatedAt, FinishedAt: activity.FinishedAt, StageStartedAt: activity.StageStartedAt,
		LastProgressAt: activity.LastProgressAt, DeadlineAt: activity.DeadlineAt, AIBatch: activity.AIBatch,
		AIBatchCount: activity.AIBatchCount, ReportIDs: activity.ReportIDs, Message: activity.Message,
		FailureReason: activity.FailureReason, Health: health, HealthMessage: healthMessage,
		ScanProgress: activity.ScanProgress, Containment: activity.Containment}
}

func activityHealth(activity Activity, now time.Time) (string, string) {
	if activity.Status != ActivityRunning {
		return "terminal", ""
	}
	stageStarted, stageErr := time.Parse(time.RFC3339Nano, activity.StageStartedAt)
	lastProgress, progressErr := time.Parse(time.RFC3339Nano, activity.LastProgressAt)
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, activity.DeadlineAt)
	isAI := activity.Stage == StageAIProviderCheck || activity.Stage == StageAIReview
	isScan := activity.Stage == StageDeterministicScan || activity.Stage == StageArtifactInspection
	if deadlineErr == nil && !now.Before(deadline) {
		if isAI {
			return "overdue", "AI provider timeout reached; shutdown is in progress"
		}
		if isScan {
			return "overdue", "Scanner deadline reached; failure handling is in progress"
		}
	}
	if isAI && stageErr == nil && deadlineErr == nil && deadline.After(stageStarted) {
		window := deadline.Sub(stageStarted)
		if !now.Before(stageStarted.Add(window * 4 / 5)) {
			return "attention", "AI provider request is taking longer than expected"
		}
	}
	if isScan && progressErr == nil {
		staleAfter := 30 * time.Second
		if stageErr == nil && deadlineErr == nil && deadline.After(stageStarted) {
			half := deadline.Sub(stageStarted) / 2
			if half < staleAfter {
				staleAfter = half
			}
		}
		if staleAfter < time.Second {
			staleAfter = time.Second
		}
		if !now.Before(lastProgress.Add(staleAfter)) {
			return "attention", "No deterministic scan progress has been recorded recently"
		}
	}
	return "active", ""
}

func webTransactionID(identity ProcessIdentity) string {
	raw, _ := json.Marshal(identity)
	return SHA256Bytes(raw)[:16]
}

func webList[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

func writeWebJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(writer).Encode(value)
}
