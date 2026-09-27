package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

func newProbeChecker(url string) *connectionChecker {
	server := &runtimeServer{config: &pluginConfig{
		SubextractorURL:    url,
		SubextractorAPIKey: "test-key",
		WebhookSecret:      "secret",
	}}
	return newConnectionChecker(newWebhookRoutes(server))
}

func runProbe(t *testing.T, checker *connectionChecker) *pb.TestConnectionResponse {
	t.Helper()
	resp, err := checker.TestConnection(context.Background(), &pb.TestConnectionRequest{
		CapabilityId: "connection-check",
	})
	if err != nil {
		t.Fatalf("TestConnection error: %v", err)
	}
	if resp == nil {
		t.Fatal("TestConnection returned nil response")
	}
	return resp
}

// fakeSubextractor serves the three probe endpoints with configurable statuses.
type fakeSubextractor struct {
	healthStatus int
	infoStatus   int
	infoBody     string
	statusStatus int
	statusBody   string
	lastAuth     string
}

func (f *fakeSubextractor) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case healthProbePath:
			if f.healthStatus == 0 {
				f.healthStatus = http.StatusOK
			}
			w.WriteHeader(f.healthStatus)
			if f.healthStatus < 300 {
				_, _ = w.Write([]byte(`{"status":"ok","service":"subextractor"}`))
			}
		case infoProbePath:
			if f.infoStatus == 0 {
				f.infoStatus = http.StatusNotFound
			}
			w.WriteHeader(f.infoStatus)
			if f.infoStatus < 300 {
				_, _ = w.Write([]byte(f.infoBody))
			}
		case siloStatusProbePath:
			f.lastAuth = r.Header.Get("Authorization")
			if f.statusStatus == 0 {
				f.statusStatus = http.StatusOK
			}
			w.WriteHeader(f.statusStatus)
			if f.statusStatus < 300 {
				_, _ = w.Write([]byte(f.statusBody))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConnectionCheckSuccess(t *testing.T) {
	fake := &fakeSubextractor{
		infoStatus: http.StatusOK,
		infoBody:   `{"success":true,"version":"2.9.3","service":"subextractor"}`,
		statusBody: `{"success":true,"configured":true,"enabled":false,"silo_url":"http://silo"}`,
	}
	srv := fake.server(t)

	resp := runProbe(t, newProbeChecker(srv.URL))
	if !resp.GetOk() {
		t.Fatalf("ok = false, message = %q", resp.GetMessage())
	}
	msg := resp.GetMessage()
	if !strings.Contains(msg, "v2.9.3") || !strings.Contains(msg, "configured: true") {
		t.Fatalf("message = %q, want version and configured:true", msg)
	}
	if fake.lastAuth != "Bearer test-key" {
		t.Fatalf("status Authorization = %q, want Bearer test-key", fake.lastAuth)
	}
}

func TestConnectionCheckConfiguredFalse(t *testing.T) {
	fake := &fakeSubextractor{
		statusBody: `{"success":true,"configured":false,"enabled":false}`,
	}
	srv := fake.server(t)

	resp := runProbe(t, newProbeChecker(srv.URL))
	if !resp.GetOk() {
		t.Fatalf("ok = false, message = %q", resp.GetMessage())
	}
	if !strings.Contains(resp.GetMessage(), "configured: false") {
		t.Fatalf("message = %q, want configured:false", resp.GetMessage())
	}
}

func TestConnectionCheckBadAPIKey(t *testing.T) {
	fake := &fakeSubextractor{statusStatus: http.StatusUnauthorized}
	srv := fake.server(t)

	resp := runProbe(t, newProbeChecker(srv.URL))
	if resp.GetOk() {
		t.Fatal("ok = true, want false for 401")
	}
	if !strings.Contains(resp.GetMessage(), "rejected the API key") {
		t.Fatalf("message = %q, want API key rejection", resp.GetMessage())
	}
}

func TestConnectionCheckStatusMissing(t *testing.T) {
	fake := &fakeSubextractor{statusStatus: http.StatusNotFound}
	srv := fake.server(t)

	resp := runProbe(t, newProbeChecker(srv.URL))
	if resp.GetOk() {
		t.Fatal("ok = true, want false for missing /api/silo/status")
	}
	if !strings.Contains(resp.GetMessage(), "older than v2.9.0") {
		t.Fatalf("message = %q, want version-too-old hint", resp.GetMessage())
	}
}

func TestConnectionCheckUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	resp := runProbe(t, newProbeChecker(url))
	if resp.GetOk() {
		t.Fatal("ok = true, want false for unreachable host")
	}
	if !strings.Contains(resp.GetMessage(), "unreachable") {
		t.Fatalf("message = %q, want unreachable", resp.GetMessage())
	}
}

func TestConnectionCheckHealthFails(t *testing.T) {
	fake := &fakeSubextractor{healthStatus: http.StatusInternalServerError}
	srv := fake.server(t)

	resp := runProbe(t, newProbeChecker(srv.URL))
	if resp.GetOk() {
		t.Fatal("ok = true, want false for failing health check")
	}
	if !strings.Contains(resp.GetMessage(), "health check failed") {
		t.Fatalf("message = %q, want health check failure", resp.GetMessage())
	}
}

func TestConnectionCheckNotConfigured(t *testing.T) {
	checker := newConnectionChecker(newWebhookRoutes(&runtimeServer{config: nil}))
	resp := runProbe(t, checker)
	if resp.GetOk() {
		t.Fatal("ok = true, want false when unconfigured")
	}
	if !strings.Contains(resp.GetMessage(), "not configured") {
		t.Fatalf("message = %q, want not configured", resp.GetMessage())
	}
}

func TestConnectionCheckRejectsInsecurePublicHTTP(t *testing.T) {
	resp := runProbe(t, newProbeChecker("http://sub.example.com:8975"))
	if resp.GetOk() {
		t.Fatal("ok = true, want false for public plain HTTP")
	}
	if !strings.Contains(resp.GetMessage(), "insecure HTTP") {
		t.Fatalf("message = %q, want insecure HTTP policy error", resp.GetMessage())
	}
}

func TestConnectionCheckListConfigOptionsEmpty(t *testing.T) {
	checker := newProbeChecker("http://subextractor:8975")
	resp, err := checker.ListConfigOptions(context.Background(), &pb.ListConfigOptionsRequest{CapabilityId: "connection-check"})
	if err != nil {
		t.Fatalf("ListConfigOptions error: %v", err)
	}
	if len(resp.GetOptionsByField()) != 0 {
		t.Fatalf("options = %v, want empty", resp.GetOptionsByField())
	}
}
