package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func ratingBody(itemID string) []byte {
	payload := map[string]any{
		"type": "rating.set",
		"rating": map[string]any{
			"rating":  8.5,
			"item_id": itemID,
		},
		"series": map[string]any{
			"id":    "s1",
			"title": "Test Series",
		},
		"profile_id": 1,
	}
	body, _ := json.Marshal(payload)
	return body
}

// signHeader builds a Stripe-convention X-Silo-Signature header value.
func signHeader(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", timestamp, hex.EncodeToString(mac.Sum(nil)))
}

func newTestRoutes(secret string) *webhookRoutes {
	server := &runtimeServer{config: &pluginConfig{
		SubextractorURL:    "http://subextractor:8975",
		SubextractorAPIKey: "test-key",
		WebhookSecret:      secret,
	}}
	return newWebhookRoutes(server)
}

func TestWebhookValidTokenAccepted(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{
		Method: "POST",
		Path:   webhookPath + "/" + deriveAuthToken("secret"),
		Body:   body,
	}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s, want 200", resp.StatusCode, string(resp.Body))
	}
	var payload struct {
		Status string `json:"status"`
		ItemID string `json:"item_id"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Status != "accepted" || payload.ItemID != "item-1" {
		t.Fatalf("payload = %#v, want accepted item-1", payload)
	}
}

func TestWebhookWrongTokenRejected(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{
		Method: "POST",
		Path:   webhookPath + "/" + deriveAuthToken("wrong-secret"),
		Body:   body,
	}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestWebhookNoTokenReturnsHint(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{Method: "POST", Path: webhookPath, Body: body}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var payload struct {
		Error string `json:"error"`
		Hint  string `json:"hint"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Error != "missing auth token" || !strings.Contains(payload.Hint, "/<auth-token>") {
		t.Fatalf("payload = %#v, want missing auth token with hint", payload)
	}
}

func TestWebhookCustomSecretIDTokenWorks(t *testing.T) {
	server := &runtimeServer{config: &pluginConfig{
		SubextractorURL:    "http://subextractor:8975",
		SubextractorAPIKey: "test-key",
		WebhookSecret:      "default-secret",
		WebhookSecrets:     map[string]string{"subex": "custom-secret"},
	}}
	routes := newWebhookRoutes(server)
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{
		Method: "POST",
		Path:   webhookPath + "/" + deriveAuthToken("custom-secret"),
		Body:   body,
	}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s, want 200", resp.StatusCode, string(resp.Body))
	}
}

func TestWebhookHeaderHMACAccepted(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{
		Method:  "POST",
		Path:    webhookPath + "/" + deriveAuthToken("secret"),
		Body:    body,
		Headers: map[string]string{webhookHeader: signHeader("secret", time.Now().Unix(), body)},
	}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s, want 200", resp.StatusCode, string(resp.Body))
	}
}

func TestWebhookHeaderHMACInvalidRejected(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{
		Method:  "POST",
		Path:    webhookPath + "/" + deriveAuthToken("secret"),
		Body:    body,
		Headers: map[string]string{webhookHeader: signHeader("wrong-secret", time.Now().Unix(), body)},
	}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestWebhookHeaderHMACExpiredRejected(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	old := time.Now().Add(-10 * time.Minute).Unix()
	req := &pb.HandleHTTPRequest{
		Method:  "POST",
		Path:    webhookPath + "/" + deriveAuthToken("secret"),
		Body:    body,
		Headers: map[string]string{webhookHeader: signHeader("secret", old, body)},
	}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestWebhookWrongTypeIgnored(t *testing.T) {
	routes := newTestRoutes("secret")
	body := []byte(`{"type":"media.added","rating":{"rating":8,"item_id":"item-1"}}`)
	req := &pb.HandleHTTPRequest{
		Method: "POST",
		Path:   webhookPath + "/" + deriveAuthToken("secret"),
		Body:   body,
	}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Status != "ignored" {
		t.Fatalf("status = %q, want ignored", payload.Status)
	}
}

func TestWebhookNoItemIDIgnored(t *testing.T) {
	routes := newTestRoutes("secret")
	body := []byte(`{"type":"rating.set","rating":{"rating":8,"item_id":""}}`)
	req := &pb.HandleHTTPRequest{
		Method: "POST",
		Path:   webhookPath + "/" + deriveAuthToken("secret"),
		Body:   body,
	}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Status != "ignored" {
		t.Fatalf("status = %q, want ignored", payload.Status)
	}
}

func TestWebhookDedupeSkipsInflight(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-dup")
	path := webhookPath + "/" + deriveAuthToken("secret")
	req := &pb.HandleHTTPRequest{Method: "POST", Path: path, Body: body}
	// First delivery starts processing.
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", resp.StatusCode)
	}
	// Second delivery while in flight is deduplicated.
	resp2, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second status = %d, want 200", resp2.StatusCode)
	}
	var payload struct {
		Status       string `json:"status"`
		Deduplicated bool   `json:"deduplicated"`
	}
	if err := json.Unmarshal(resp2.Body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Status != "accepted" || !payload.Deduplicated {
		t.Fatalf("payload = %#v, want accepted with deduplicated=true", payload)
	}
}

func TestWebhookNotConfigured(t *testing.T) {
	server := &runtimeServer{config: nil}
	routes := newWebhookRoutes(server)
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{
		Method: "POST",
		Path:   webhookPath + "/" + deriveAuthToken("secret"),
		Body:   body,
	}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestStatusRequiresAdmin(t *testing.T) {
	routes := newTestRoutes("secret")
	// Non-admin gets 403.
	resp, err := routes.Handle(context.Background(), &pb.HandleHTTPRequest{Method: "GET", Path: statusPath})
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	// Admin gets 200 with configured=true.
	resp2, err := routes.Handle(context.Background(), &pb.HandleHTTPRequest{
		Method:  "GET",
		Path:    statusPath,
		Headers: map[string]string{adminRoleHeader: "admin"},
	})
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp2.StatusCode)
	}
	var payload struct {
		Version    string `json:"version"`
		Configured bool   `json:"configured"`
		Enabled    bool   `json:"enabled"`
	}
	if err := json.Unmarshal(resp2.Body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Version != "0.2.0" || !payload.Configured || !payload.Enabled {
		t.Fatalf("payload = %#v, want version 0.2.0 configured=true enabled=true", payload)
	}
}

func TestAdminTokenEndpoint(t *testing.T) {
	server := &runtimeServer{config: &pluginConfig{
		SubextractorURL:    "http://subextractor:8975",
		SubextractorAPIKey: "test-key",
		WebhookSecret:      "default-secret",
		WebhookSecrets:     map[string]string{"subex": "custom-secret"},
	}}
	routes := newWebhookRoutes(server)
	// Non-admin gets 403.
	resp, err := routes.Handle(context.Background(), &pb.HandleHTTPRequest{Method: "GET", Path: adminTokenPath})
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	// Admin gets derived tokens keyed by id, never raw secrets.
	resp2, err := routes.Handle(context.Background(), &pb.HandleHTTPRequest{
		Method:  "GET",
		Path:    adminTokenPath,
		Headers: map[string]string{adminRoleHeader: "admin"},
	})
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp2.StatusCode)
	}
	var payload struct {
		Tokens map[string]string `json:"tokens"`
	}
	if err := json.Unmarshal(resp2.Body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Tokens["default"] != deriveAuthToken("default-secret") {
		t.Fatalf("default token = %q, want derived from default-secret", payload.Tokens["default"])
	}
	if payload.Tokens["subex"] != deriveAuthToken("custom-secret") {
		t.Fatalf("subex token = %q, want derived from custom-secret", payload.Tokens["subex"])
	}
	if strings.Contains(string(resp2.Body), "default-secret") || strings.Contains(string(resp2.Body), "custom-secret") {
		t.Fatalf("token endpoint leaked raw secrets: %s", string(resp2.Body))
	}
}

func TestUnknownPath404(t *testing.T) {
	routes := newTestRoutes("secret")
	resp, err := routes.Handle(context.Background(), &pb.HandleHTTPRequest{
		Method:  "GET",
		Path:    "/nope",
		Headers: map[string]string{adminRoleHeader: "admin"},
	})
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestVerifyHeaderSignature(t *testing.T) {
	secret := "s3cret"
	body := []byte(`{"hello":"world"}`)
	now := time.Now().Unix()
	valid := signHeader(secret, now, body)
	if !verifyHeaderSignature(secret, body, valid) {
		t.Fatal("valid signature rejected")
	}
	if verifyHeaderSignature("other", body, valid) {
		t.Fatal("signature with wrong secret accepted")
	}
	if verifyHeaderSignature(secret, []byte(`{"hello":"tampered"}`), valid) {
		t.Fatal("signature for tampered body accepted")
	}
	if verifyHeaderSignature(secret, body, "t=abc,v1=deadbeef") {
		t.Fatal("malformed timestamp accepted")
	}
	if verifyHeaderSignature(secret, body, "v1=deadbeef") {
		t.Fatal("missing timestamp accepted")
	}
	if verifyHeaderSignature(secret, body, "") {
		t.Fatal("empty header accepted")
	}
	if verifyHeaderSignature(secret, body, signHeader(secret, now-1000, body)) {
		t.Fatal("expired signature accepted")
	}
}

func TestDeriveAuthTokenDeterministic(t *testing.T) {
	a := deriveAuthToken("secret")
	b := deriveAuthToken("secret")
	if a != b || len(a) != 64 {
		t.Fatalf("deriveAuthToken not deterministic 64-hex: %q vs %q", a, b)
	}
	if a == deriveAuthToken("other") {
		t.Fatal("deriveAuthToken collision for different secrets")
	}
}

func TestSubextractorEndpointPolicy(t *testing.T) {
	cases := []struct {
		raw string
		ok  bool
	}{
		{"http://subextractor:8975", true},
		{"http://localhost:8975", true},
		{"http://127.0.0.1:8975", true},
		{"http://192.168.1.10:8975", true},
		{"https://sub.example.com", true},
		{"http://sub.example.com", false},
		{"ftp://sub.example.com", false},
		{"", false},
	}
	for _, tc := range cases {
		got, err := subextractorEndpoint(tc.raw)
		if tc.ok && err != nil {
			t.Fatalf("subextractorEndpoint(%q) error: %v", tc.raw, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("subextractorEndpoint(%q) = %q, want error", tc.raw, got)
		}
		if tc.ok && !strings.HasSuffix(got, "/api/silo/process") {
			t.Fatalf("subextractorEndpoint(%q) = %q, want suffix /api/silo/process", tc.raw, got)
		}
	}
}

// --- enabled toggle -----------------------------------------------------

func TestConfigureEnabledDefaultTrue(t *testing.T) {
	server := &runtimeServer{}
	if !server.isEnabled() {
		t.Fatal("zero-value runtimeServer should be enabled")
	}
	value, _ := structpb.NewStruct(map[string]any{
		"subextractor_url":     "http://subextractor:8975",
		"subextractor_api_key": "k",
		"webhook_secret":       "s",
	})
	if _, err := server.Configure(context.Background(), &pb.ConfigureRequest{
		Config: []*pb.ConfigEntry{{Key: configKey, Value: value}},
	}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if !server.isEnabled() {
		t.Fatal("enabled should default to true when the field is absent")
	}
}

func TestConfigureDisabled(t *testing.T) {
	server := &runtimeServer{}
	value, _ := structpb.NewStruct(map[string]any{
		"enabled":              false,
		"subextractor_url":     "http://subextractor:8975",
		"subextractor_api_key": "k",
		"webhook_secret":       "s",
	})
	if _, err := server.Configure(context.Background(), &pb.ConfigureRequest{
		Config: []*pb.ConfigEntry{{Key: configKey, Value: value}},
	}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if server.isEnabled() {
		t.Fatal("enabled=false should disable the plugin")
	}
	if server.config == nil {
		t.Fatal("connection should still be stored while disabled")
	}
}

func TestWebhookDisabledReturns503(t *testing.T) {
	server := &runtimeServer{
		config: &pluginConfig{
			SubextractorURL:    "http://subextractor:8975",
			SubextractorAPIKey: "test-key",
			WebhookSecret:      "secret",
		},
		disabled: true,
	}
	routes := newWebhookRoutes(server)
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{
		Method: "POST",
		Path:   webhookPath + "/" + deriveAuthToken("secret"),
		Body:   body,
	}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Error != "disabled" {
		t.Fatalf("error = %q, want disabled", payload.Error)
	}
	// Exact /webhook without a token keeps its 400 hint even when disabled.
	noToken, err := routes.Handle(context.Background(), &pb.HandleHTTPRequest{Method: "POST", Path: webhookPath, Body: body})
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if noToken.StatusCode != http.StatusBadRequest {
		t.Fatalf("no-token status = %d, want 400", noToken.StatusCode)
	}
}

func TestStatusReportsDisabled(t *testing.T) {
	server := &runtimeServer{
		config: &pluginConfig{
			SubextractorURL:    "http://subextractor:8975",
			SubextractorAPIKey: "test-key",
			WebhookSecret:      "secret",
		},
		disabled: true,
	}
	routes := newWebhookRoutes(server)
	resp, err := routes.Handle(context.Background(), &pb.HandleHTTPRequest{
		Method:  "GET",
		Path:    statusPath,
		Headers: map[string]string{adminRoleHeader: "admin"},
	})
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	var payload struct {
		Version    string `json:"version"`
		Configured bool   `json:"configured"`
		Enabled    bool   `json:"enabled"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Version != "0.2.0" || !payload.Configured || payload.Enabled {
		t.Fatalf("payload = %#v, want version 0.2.0 configured=true enabled=false", payload)
	}
}

// --- watch-sync favorite trigger ----------------------------------------

func newTestSubextractor(t *testing.T) (*httptest.Server, <-chan subextractorRequest) {
	t.Helper()
	received := make(chan subextractorRequest, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/silo/process" {
			http.NotFound(w, r)
			return
		}
		var body subextractorRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, received
}

func newWatchRoutes(url string) (*webhookRoutes, *watchSyncProvider) {
	server := &runtimeServer{config: &pluginConfig{
		SubextractorURL:    url,
		SubextractorAPIKey: "test-key",
		WebhookSecret:      "secret",
	}}
	routes := newWebhookRoutes(server)
	return routes, newWatchSyncProvider(routes)
}

func favoriteEvent(eventID, mediaID string, mediaType pb.WatchSyncMediaType, title string) *pb.WatchSyncEvent {
	return &pb.WatchSyncEvent{
		EventId:   eventID,
		Operation: pb.WatchSyncOperation_WATCH_SYNC_OPERATION_ADD_FAVORITE,
		Media: &pb.WatchSyncMedia{
			MediaItemId: mediaID,
			MediaType:   mediaType,
			Title:       title,
		},
	}
}

func waitForCall(t *testing.T, ch <-chan subextractorRequest) subextractorRequest {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SubExtractor call")
		return subextractorRequest{}
	}
}

func assertNoCall(t *testing.T, ch <-chan subextractorRequest) {
	t.Helper()
	select {
	case got := <-ch:
		t.Fatalf("unexpected SubExtractor call: %#v", got)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestWatchSyncFavoriteAddMovieTriggers(t *testing.T) {
	srv, received := newTestSubextractor(t)
	_, watch := newWatchRoutes(srv.URL)
	resp, err := watch.ApplyEvents(context.Background(), &pb.WatchSyncApplyEventsRequest{
		Events: []*pb.WatchSyncEvent{
			favoriteEvent("e1", "movie-1", pb.WatchSyncMediaType_WATCH_SYNC_MEDIA_TYPE_MOVIE, "The Movie"),
		},
	})
	if err != nil {
		t.Fatalf("ApplyEvents: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].GetStatus() != pb.WatchSyncApplyStatus_WATCH_SYNC_APPLY_STATUS_APPLIED {
		t.Fatalf("results = %#v, want one APPLIED", resp.Results)
	}
	got := waitForCall(t, received)
	if got.ItemID != "movie-1" || got.Title != "The Movie" {
		t.Fatalf("call = %#v, want movie-1/The Movie", got)
	}
}

func TestWatchSyncFavoriteAddEpisodeTriggers(t *testing.T) {
	srv, received := newTestSubextractor(t)
	_, watch := newWatchRoutes(srv.URL)
	_, err := watch.ApplyEvents(context.Background(), &pb.WatchSyncApplyEventsRequest{
		Events: []*pb.WatchSyncEvent{
			favoriteEvent("e1", "episode-1", pb.WatchSyncMediaType_WATCH_SYNC_MEDIA_TYPE_EPISODE, "S01E02"),
		},
	})
	if err != nil {
		t.Fatalf("ApplyEvents: %v", err)
	}
	got := waitForCall(t, received)
	if got.ItemID != "episode-1" || got.Title != "S01E02" {
		t.Fatalf("call = %#v, want episode-1/S01E02", got)
	}
}

func TestWatchSyncSeriesFavoriteIgnored(t *testing.T) {
	srv, received := newTestSubextractor(t)
	_, watch := newWatchRoutes(srv.URL)
	resp, err := watch.ApplyEvents(context.Background(), &pb.WatchSyncApplyEventsRequest{
		Events: []*pb.WatchSyncEvent{
			favoriteEvent("e1", "series-1", pb.WatchSyncMediaType_WATCH_SYNC_MEDIA_TYPE_UNSPECIFIED, "A Series"),
		},
	})
	if err != nil {
		t.Fatalf("ApplyEvents: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].GetStatus() != pb.WatchSyncApplyStatus_WATCH_SYNC_APPLY_STATUS_NO_CHANGE {
		t.Fatalf("results = %#v, want one NO_CHANGE", resp.Results)
	}
	assertNoCall(t, received)
}

func TestWatchSyncFavoriteRemoveIgnored(t *testing.T) {
	srv, received := newTestSubextractor(t)
	_, watch := newWatchRoutes(srv.URL)
	event := favoriteEvent("e1", "movie-1", pb.WatchSyncMediaType_WATCH_SYNC_MEDIA_TYPE_MOVIE, "The Movie")
	event.Operation = pb.WatchSyncOperation_WATCH_SYNC_OPERATION_REMOVE_FAVORITE
	resp, err := watch.ApplyEvents(context.Background(), &pb.WatchSyncApplyEventsRequest{
		Events: []*pb.WatchSyncEvent{event},
	})
	if err != nil {
		t.Fatalf("ApplyEvents: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].GetStatus() != pb.WatchSyncApplyStatus_WATCH_SYNC_APPLY_STATUS_NO_CHANGE {
		t.Fatalf("results = %#v, want one NO_CHANGE", resp.Results)
	}
	assertNoCall(t, received)
}

func TestWatchSyncDisabledIgnored(t *testing.T) {
	srv, received := newTestSubextractor(t)
	server := &runtimeServer{
		config: &pluginConfig{
			SubextractorURL:    srv.URL,
			SubextractorAPIKey: "test-key",
			WebhookSecret:      "secret",
		},
		disabled: true,
	}
	routes := newWebhookRoutes(server)
	watch := newWatchSyncProvider(routes)
	resp, err := watch.ApplyEvents(context.Background(), &pb.WatchSyncApplyEventsRequest{
		Events: []*pb.WatchSyncEvent{
			favoriteEvent("e1", "movie-1", pb.WatchSyncMediaType_WATCH_SYNC_MEDIA_TYPE_MOVIE, "The Movie"),
		},
	})
	if err != nil {
		t.Fatalf("ApplyEvents: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].GetStatus() != pb.WatchSyncApplyStatus_WATCH_SYNC_APPLY_STATUS_NO_CHANGE {
		t.Fatalf("results = %#v, want one NO_CHANGE", resp.Results)
	}
	assertNoCall(t, received)
}

func TestWatchSyncFavoriteDedupe(t *testing.T) {
	release := make(chan struct{})
	received := make(chan subextractorRequest, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body subextractorRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		received <- body
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, watch := newWatchRoutes(srv.URL)
	if _, err := watch.ApplyEvents(context.Background(), &pb.WatchSyncApplyEventsRequest{
		Events: []*pb.WatchSyncEvent{
			favoriteEvent("e1", "dup-1", pb.WatchSyncMediaType_WATCH_SYNC_MEDIA_TYPE_MOVIE, "Dup"),
		},
	}); err != nil {
		t.Fatalf("first ApplyEvents: %v", err)
	}
	// First call is now blocked in the handler, so dup-1 stays in flight.
	waitForCall(t, received)

	if _, err := watch.ApplyEvents(context.Background(), &pb.WatchSyncApplyEventsRequest{
		Events: []*pb.WatchSyncEvent{
			favoriteEvent("e2", "dup-1", pb.WatchSyncMediaType_WATCH_SYNC_MEDIA_TYPE_MOVIE, "Dup"),
		},
	}); err != nil {
		t.Fatalf("second ApplyEvents: %v", err)
	}
	assertNoCall(t, received)
	close(release)
}
