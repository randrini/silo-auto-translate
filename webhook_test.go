package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// signPath builds the HMAC digest over "<epoch>.<body>" and returns the full
// signed webhook path: /webhook/sig:<secretId>/ts:<epoch>/v1:<hex>.
func signPath(secretID, secret string, epoch int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(epoch, 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	digest := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s/sig:%s/ts:%d/v1:%s", webhookPath, secretID, epoch, digest)
}

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

func newTestRoutes(secret string) *webhookRoutes {
	server := &runtimeServer{config: &pluginConfig{
		SubextractorURL:    "http://subextractor:8975",
		SubextractorAPIKey: "test-key",
		WebhookSecret:      secret,
	}}
	return newWebhookRoutes(server)
}

func TestWebhookValidSignatureInPathAccepted(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{
		Method: "POST",
		Path:   signPath("default", "secret", time.Now().Unix(), body),
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

func TestWebhookCustomSecretIDFromWebhookSecrets(t *testing.T) {
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
		Path:   signPath("subex", "custom-secret", time.Now().Unix(), body),
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

func TestWebhookUnknownSecretIDRejected(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{
		Method: "POST",
		Path:   signPath("nope", "secret", time.Now().Unix(), body),
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

func TestWebhookInvalidDigestRejected(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	path := signPath("default", "wrong-secret", time.Now().Unix(), body)
	req := &pb.HandleHTTPRequest{Method: "POST", Path: path, Body: body}
	resp, err := routes.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestWebhookExpiredTimestampRejected(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	old := time.Now().Add(-10 * time.Minute).Unix()
	req := &pb.HandleHTTPRequest{
		Method: "POST",
		Path:   signPath("default", "secret", old, body),
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

func TestWebhookMalformedPathRejected(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	now := time.Now().Unix()
	cases := []string{
		webhookPath + "/ts:" + strconv.FormatInt(now, 10) + "/v1:deadbeef", // missing sig
		webhookPath + "/sig:default/v1:deadbeef",                            // missing ts
		webhookPath + "/sig:default/ts:abc/v1:deadbeef",                     // bad ts
		webhookPath + "/sig:default/ts:" + strconv.FormatInt(now, 10),       // missing v1
		webhookPath + "/sig:default/ts:" + strconv.FormatInt(now, 10) + "/v1:zz", // bad digest
	}
	for _, path := range cases {
		req := &pb.HandleHTTPRequest{Method: "POST", Path: path, Body: body}
		resp, err := routes.Handle(context.Background(), req)
		if err != nil {
			t.Fatalf("Handle error for %q: %v", path, err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("path %q status = %d, want 400", path, resp.StatusCode)
		}
	}
}

func TestWebhookExactPathReturnsHint(t *testing.T) {
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
	if payload.Error != "missing signature token" || !strings.Contains(payload.Hint, "/webhook/sig:") {
		t.Fatalf("payload = %#v, want missing signature token with hint", payload)
	}
}

func TestWebhookWrongTypeIgnored(t *testing.T) {
	routes := newTestRoutes("secret")
	body := []byte(`{"type":"media.added","rating":{"rating":8,"item_id":"item-1"}}`)
	req := &pb.HandleHTTPRequest{
		Method: "POST",
		Path:   signPath("default", "secret", time.Now().Unix(), body),
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
		Path:   signPath("default", "secret", time.Now().Unix(), body),
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
	path := signPath("default", "secret", time.Now().Unix(), body)
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
		Path:   signPath("default", "secret", time.Now().Unix(), body),
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
	}
	if err := json.Unmarshal(resp2.Body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Version != "0.1.1" || !payload.Configured {
		t.Fatalf("payload = %#v, want version 0.1.1 configured=true", payload)
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

func TestVerifySignature(t *testing.T) {
	secret := "s3cret"
	body := []byte(`{"hello":"world"}`)
	now := time.Now().Unix()
	valid := signPath("default", secret, now, body)
	// Extract the digest from the path and verify.
	digest := strings.TrimPrefix(strings.Split(valid, "/v1:")[1], "")
	if !verifySignature(secret, body, now, digest) {
		t.Fatal("valid signature rejected")
	}
	if verifySignature("other", body, now, digest) {
		t.Fatal("signature with wrong secret accepted")
	}
	if verifySignature(secret, []byte(`{"hello":"tampered"}`), now, digest) {
		t.Fatal("signature for tampered body accepted")
	}
	if verifySignature(secret, body, now-1000, digest) {
		t.Fatal("expired signature accepted")
	}
	if verifySignature(secret, body, now, "deadbeef") {
		t.Fatal("malformed digest accepted")
	}
	if verifySignature("", body, now, digest) {
		t.Fatal("empty secret accepted")
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
