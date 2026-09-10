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

func sign(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", timestamp, hex.EncodeToString(mac.Sum(nil)))
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

func TestWebhookValidSignatureAccepted(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{
		Method:  "POST",
		Path:    webhookPath,
		Body:    body,
		Headers: map[string]string{webhookHeader: sign("secret", time.Now().Unix(), body)},
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

func TestWebhookInvalidSignatureRejected(t *testing.T) {
	routes := newTestRoutes("secret")
	body := ratingBody("item-1")
	req := &pb.HandleHTTPRequest{
		Method:  "POST",
		Path:    webhookPath,
		Body:    body,
		Headers: map[string]string{webhookHeader: sign("wrong-secret", time.Now().Unix(), body)},
	}
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
		Method:  "POST",
		Path:    webhookPath,
		Body:    body,
		Headers: map[string]string{webhookHeader: sign("secret", old, body)},
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
		Method:  "POST",
		Path:    webhookPath,
		Body:    body,
		Headers: map[string]string{webhookHeader: sign("secret", time.Now().Unix(), body)},
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
		Method:  "POST",
		Path:    webhookPath,
		Body:    body,
		Headers: map[string]string{webhookHeader: sign("secret", time.Now().Unix(), body)},
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
	req := &pb.HandleHTTPRequest{
		Method:  "POST",
		Path:    webhookPath,
		Body:    body,
		Headers: map[string]string{webhookHeader: sign("secret", time.Now().Unix(), body)},
	}
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
		Status      string `json:"status"`
		Deduplicated bool  `json:"deduplicated"`
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
		Method:  "POST",
		Path:    webhookPath,
		Body:    body,
		Headers: map[string]string{webhookHeader: sign("secret", time.Now().Unix(), body)},
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
	if payload.Version != "0.1.0" || !payload.Configured {
		t.Fatalf("payload = %#v, want version 0.1.0 configured=true", payload)
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
	valid := sign(secret, now, body)
	if !verifySignature(secret, body, valid) {
		t.Fatal("valid signature rejected")
	}
	if verifySignature("other", body, valid) {
		t.Fatal("signature with wrong secret accepted")
	}
	if verifySignature(secret, []byte(`{"hello":"tampered"}`), valid) {
		t.Fatal("signature for tampered body accepted")
	}
	if verifySignature(secret, body, "t=abc,v1=deadbeef") {
		t.Fatal("malformed timestamp accepted")
	}
	if verifySignature(secret, body, "v1=deadbeef") {
		t.Fatal("missing timestamp accepted")
	}
	if verifySignature(secret, body, "") {
		t.Fatal("empty header accepted")
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
