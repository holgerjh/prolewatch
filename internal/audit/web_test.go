package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func webRequest(t *testing.T, handler http.Handler, method, path, host, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "http://"+host+path, nil)
	request.Host = host
	request.RemoteAddr = "127.0.0.1:45678"
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestWebSecurityBoundaryAndEmbeddedAssets(t *testing.T) {
	withStateAndShare(t)
	token := strings.Repeat("a", 64)
	server, err := newWebServer("127.0.0.1:8123", token)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.handler()
	if response := webRequest(t, handler, http.MethodGet, "/", server.host, ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "AUR build review") {
		t.Fatalf("embedded index unavailable: %d %s", response.Code, response.Body.String())
	}
	for _, path := range []string{"/app.css", "/app.js", "/logo.png"} {
		if response := webRequest(t, handler, http.MethodGet, path, server.host, ""); response.Code != http.StatusOK || response.Body.Len() == 0 {
			t.Fatalf("embedded asset %s unavailable: %d", path, response.Code)
		}
	}
	if response := webRequest(t, handler, http.MethodGet, "/api/overview", server.host, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status=%d", response.Code)
	}
	if response := webRequest(t, handler, http.MethodGet, "/api/overview", server.host, strings.Repeat("b", 64)); response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status=%d", response.Code)
	}
	rawTokenRequest := httptest.NewRequest(http.MethodGet, "http://"+server.host+"/api/overview", nil)
	rawTokenRequest.Host, rawTokenRequest.RemoteAddr = server.host, "127.0.0.1:45678"
	rawTokenRequest.Header.Set("Authorization", token)
	rawTokenResponse := httptest.NewRecorder()
	handler.ServeHTTP(rawTokenResponse, rawTokenRequest)
	if rawTokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("token without Bearer scheme status=%d", rawTokenResponse.Code)
	}
	if response := webRequest(t, handler, http.MethodPost, "/api/overview", server.host, token); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("mutating method status=%d", response.Code)
	}
	if response := webRequest(t, handler, http.MethodGet, "/api/overview", "localhost:8123", token); response.Code != http.StatusForbidden {
		t.Fatalf("wrong Host status=%d", response.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "http://"+server.host+"/api/overview", nil)
	request.Host, request.RemoteAddr = server.host, "192.0.2.10:1234"
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-loopback client status=%d", response.Code)
	}
	allowed := webRequest(t, handler, http.MethodGet, "/api/overview", server.host, token)
	if allowed.Code != http.StatusOK || allowed.Header().Get("Content-Security-Policy") == "" || allowed.Header().Get("Cache-Control") != "no-store" || allowed.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("overview headers/status invalid: %d %#v", allowed.Code, allowed.Header())
	}
}

func TestRunWebValidatesArgumentsAndShutsDownCleanly(t *testing.T) {
	for _, args := range [][]string{
		{"--port", "-1"},
		{"--port", "65536"},
		{"--port", "not-a-port"},
		{"unexpected"},
	} {
		if status := runWeb(context.Background(), args); status != 20 {
			t.Fatalf("runWeb(%q) status=%d, want 20", args, status)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if status := runWeb(ctx, []string{"--port", "0"}); status != 0 {
		t.Fatalf("clean dashboard shutdown status=%d", status)
	}
}

func TestNewWebServerRejectsNonLoopbackIdentity(t *testing.T) {
	token := strings.Repeat("a", 64)
	for _, test := range []struct {
		host  string
		token string
	}{
		{host: "localhost:8123", token: token},
		{host: "0.0.0.0:8123", token: token},
		{host: "127.0.0.1", token: token},
		{host: "127.0.0.1:8123", token: "short"},
	} {
		if _, err := newWebServer(test.host, test.token); err == nil {
			t.Fatalf("accepted unsafe web identity host=%q token-length=%d", test.host, len(test.token))
		}
	}
}

func TestWebOverviewAndReportAPIsExposeValidatedSummaries(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	service, err := NewAuditService(context.Background(), DefaultConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 {
		t.Fatalf("report fixture failed: %d %v", status, err)
	}
	recorder, err := NewActivityRecorder("demo", "scan", "pre")
	if err != nil {
		t.Fatal(err)
	}
	recorder.LinkReport(report.ReportID)
	recorder.Finish(ActivityAllowed, "complete")

	token := strings.Repeat("c", 64)
	server, err := newWebServer("127.0.0.1:8124", token)
	if err != nil {
		t.Fatal(err)
	}
	previousIdentity := webCleanRootIdentity
	webCleanRootIdentity = func() (CleanRootPolicyIdentity, error) {
		return CleanRootPolicyIdentity{Available: true, Generation: "1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestSHA256: strings.Repeat("d", 64)}, nil
	}
	t.Cleanup(func() { webCleanRootIdentity = previousIdentity })

	overviewResponse := webRequest(t, server.handler(), http.MethodGet, "/api/overview", server.host, token)
	if overviewResponse.Code != http.StatusOK {
		t.Fatal(overviewResponse.Body.String())
	}
	var overview webOverview
	if err := json.Unmarshal(overviewResponse.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if overview.CleanRoot.Status != "available" || len(overview.Activities) != 1 || overview.Activities[0].Health != "terminal" ||
		overview.Activities[0].StageStartedAt == "" || overview.Activities[0].LastProgressAt == "" ||
		len(overview.Reports) != 1 || overview.Reports[0].ReportID != report.ReportID {
		t.Fatalf("unexpected overview: %#v", overview)
	}
	detailResponse := webRequest(t, server.handler(), http.MethodGet, "/api/reports/"+report.ReportID, server.host, token)
	if detailResponse.Code != http.StatusOK || strings.Contains(detailResponse.Body.String(), `"manifest":`) || !strings.Contains(detailResponse.Body.String(), `"findings":`) {
		t.Fatalf("report detail shape is unsafe: %d %s", detailResponse.Code, detailResponse.Body.String())
	}
	var detailJSON map[string]json.RawMessage
	if err := json.Unmarshal(detailResponse.Body.Bytes(), &detailJSON); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"exclusions", "findings", "manifest_diff", "sealed_artifacts", "sandbox_runs", "sources"} {
		value, ok := detailJSON[field]
		if !ok || len(value) == 0 || value[0] != '[' {
			t.Fatalf("report detail field %q is not an array: %s", field, value)
		}
	}
	var detail webReportDetail
	if err := json.Unmarshal(detailResponse.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Reviewer.Verdicts) != 1 || detail.Reviewer.Verdicts[0].Summary != "safe" || detail.Reviewer.Verdicts[0].Confidence != "high" {
		t.Fatalf("validated AI verdict missing from report detail: %#v", detail.Reviewer)
	}
	rawResponse := webRequest(t, server.handler(), http.MethodGet, "/api/reports/"+report.ReportID+"/raw", server.host, token)
	if rawResponse.Code != http.StatusOK || !strings.Contains(rawResponse.Body.String(), `"manifest":`) || rawResponse.Header().Get("Content-Disposition") == "" {
		t.Fatalf("raw report unavailable: %d %s", rawResponse.Code, rawResponse.Body.String())
	}
	for _, path := range []string{"/api/reports/../../etc/passwd", "/api/reports/not-an-id", "/api/reports/" + report.ReportID + "/extra"} {
		if response := webRequest(t, server.handler(), http.MethodGet, path, server.host, token); response.Code != http.StatusNotFound {
			t.Fatalf("unsafe report path %q status=%d", path, response.Code)
		}
	}

	corruptID := "20260812T010203Z-aaaaaaaaaaaa-cccccccc"
	if err := os.WriteFile(filepath.Join(NewReportStore().Root, corruptID+".json"), []byte(`{"report_id":"`+corruptID+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if response := webRequest(t, server.handler(), http.MethodGet, "/api/reports/"+corruptID, server.host, token); response.Code != http.StatusNotFound {
		t.Fatalf("corrupt report status=%d", response.Code)
	}
}

func TestWebPayloadNeverContainsCleanRootSecrets(t *testing.T) {
	manifest := validTestCleanRootManifest()
	identity, err := IdentityForPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	activity := Activity{SchemaVersion: 1, ActivityID: "20260812T010203Z-eeeeeeeeeeeeeeee", Transaction: identity, Worker: identity,
		PackageBase: "demo", Kind: "makepkg", Phase: "build", Stage: StageSandboxExecution, Status: ActivityRunning,
		StartedAt: UTCNow(), UpdatedAt: UTCNow(), ReportIDs: []string{}, Containment: ActivityContainment{CleanRootState: "prepared",
			CleanRootGeneration: manifest.Generation, CleanRootManifest: manifest.ManifestSHA256, PackageCount: len(manifest.Packages),
			ArtifactCount: len(manifest.ArtifactHashes), SandboxState: "running", Supervisor: "systemd-user", NetworkPolicy: "isolated"}}
	raw, err := json.Marshal(activityForWeb(activity))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"build-jobs", "root_path", "cleanup", "token"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("web activity leaked %q: %s", secret, raw)
		}
	}
}

func TestActivityHealthUsesConservativeBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	activity := testActivity(t, "20260812T010203Z-ffffffffffffffff")
	activity.StartedAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	activity.StageStartedAt = activity.StartedAt
	activity.UpdatedAt = now.Format(time.RFC3339Nano)
	activity.LastProgressAt = now.Add(-29 * time.Second).Format(time.RFC3339Nano)
	activity.DeadlineAt = now.Add(4 * time.Minute).Format(time.RFC3339Nano)
	if health, _ := activityHealth(activity, now); health != "active" {
		t.Fatalf("fresh scan health=%q", health)
	}
	activity.LastProgressAt = now.Add(-30 * time.Second).Format(time.RFC3339Nano)
	if health, _ := activityHealth(activity, now); health != "attention" {
		t.Fatalf("stale scan health=%q", health)
	}
	activity.DeadlineAt = now.Format(time.RFC3339Nano)
	if health, _ := activityHealth(activity, now); health != "overdue" {
		t.Fatalf("overdue scan health=%q", health)
	}

	activity.Stage = StageAIReview
	activity.StageStartedAt = now.Add(-80 * time.Second).Format(time.RFC3339Nano)
	activity.LastProgressAt = activity.StageStartedAt
	activity.DeadlineAt = now.Add(20 * time.Second).Format(time.RFC3339Nano)
	if health, _ := activityHealth(activity, now); health != "attention" {
		t.Fatalf("slow AI health=%q", health)
	}
	activity.StageStartedAt = now.Add(-79 * time.Second).Format(time.RFC3339Nano)
	activity.LastProgressAt = activity.StageStartedAt
	activity.DeadlineAt = now.Add(21 * time.Second).Format(time.RFC3339Nano)
	if health, _ := activityHealth(activity, now); health != "active" {
		t.Fatalf("normal AI health=%q", health)
	}
	activity.Status = ActivityFailed
	if health, _ := activityHealth(activity, now); health != "terminal" {
		t.Fatalf("terminal health=%q", health)
	}
}
