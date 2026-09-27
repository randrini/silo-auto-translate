package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	pb "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/hashicorp/go-hclog"
)

const (
	// connectionCheckTimeout bounds the whole probe (all requests share it).
	connectionCheckTimeout = 10 * time.Second
	healthProbePath        = "/api/health"
	infoProbePath          = "/api/info"
	siloStatusProbePath    = "/api/silo/status"
	maxProbeBody           = 64 << 10
)

// connectionChecker implements the host's "Check Connection" button. The host
// probes a plugin's connection test through the request_router.v1 capability
// (RequestRouter.TestConnection); declaring that capability is what turns the
// admin UI's "Connection checks are not supported for this plugin yet" into a
// real probe. Only TestConnection (and an empty ListConfigOptions) are
// implemented — the router RPCs are never exercised because this plugin is not
// used as a media request router.
type connectionChecker struct {
	pb.UnimplementedRequestRouterServer
	routes *webhookRoutes
	logger hclog.Logger
}

func newConnectionChecker(routes *webhookRoutes) *connectionChecker {
	return &connectionChecker{
		routes: routes,
		logger: hclog.New(&hclog.LoggerOptions{Name: "silo-auto-translate-connection"}),
	}
}

// TestConnection verifies the candidate/stored SubExtractor config: it must be
// reachable (/api/health) and accept the API key on /api/silo/status (the
// endpoint that reports whether SubExtractor's silo integration is configured).
func (c *connectionChecker) TestConnection(ctx context.Context, _ *pb.TestConnectionRequest) (*pb.TestConnectionResponse, error) {
	cfg := c.routes.currentConfig()
	if cfg == nil {
		return &pb.TestConnectionResponse{
			Ok:      false,
			Message: "SubExtractor is not configured: URL, API key, and webhook secret are all required.",
		}, nil
	}
	message, err := c.probe(ctx, cfg)
	if err != nil {
		return &pb.TestConnectionResponse{Ok: false, Message: err.Error()}, nil
	}
	return &pb.TestConnectionResponse{Ok: true, Message: message}, nil
}

// ListConfigOptions returns no dynamic options. It exists so the host's
// config-options probe degrades gracefully now that a request_router.v1
// capability is declared; this plugin has no dynamic SELECT fields.
func (c *connectionChecker) ListConfigOptions(context.Context, *pb.ListConfigOptionsRequest) (*pb.ListConfigOptionsResponse, error) {
	return &pb.ListConfigOptionsResponse{}, nil
}

func (c *connectionChecker) probe(ctx context.Context, cfg *pluginConfig) (string, error) {
	base, err := subextractorURL(cfg.SubextractorURL, "")
	if err != nil {
		return "", err
	}
	base = strings.TrimRight(base, "/")

	probeCtx, cancel := context.WithTimeout(ctx, connectionCheckTimeout)
	defer cancel()
	client := &http.Client{Timeout: connectionCheckTimeout}

	healthStatus, _, err := probeGet(probeCtx, client, base+healthProbePath, "")
	if err != nil {
		return "", fmt.Errorf("SubExtractor unreachable at %s: %v", base, err)
	}
	if healthStatus < 200 || healthStatus >= 300 {
		return "", fmt.Errorf("SubExtractor health check failed at %s (HTTP %d)", base, healthStatus)
	}

	statusCode, statusBody, err := probeGet(probeCtx, client, base+siloStatusProbePath, cfg.SubextractorAPIKey)
	if err != nil {
		return "", fmt.Errorf("SubExtractor did not answer /api/silo/status: %v", err)
	}
	switch {
	case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
		return "", fmt.Errorf("SubExtractor rejected the API key (HTTP %d): check subextractor_api_key", statusCode)
	case statusCode == http.StatusNotFound:
		return "", errors.New("SubExtractor is older than v2.9.0: /api/silo/status is missing (HTTP 404)")
	case statusCode < 200 || statusCode >= 300:
		return "", fmt.Errorf("SubExtractor /api/silo/status failed (HTTP %d)", statusCode)
	}

	configured, _ := parseSiloStatus(statusBody)
	version := parseVersion(statusBody)
	if version == "" {
		// /api/health and /api/silo/status omit the version; /api/info is
		// auth-exempt and best-effort.
		version = c.fetchVersion(probeCtx, client, base)
	}

	message := "SubExtractor reachable"
	if version != "" {
		message += fmt.Sprintf(" (v%s)", version)
	}
	message += fmt.Sprintf("; silo integration configured: %t", configured)
	if !configured {
		message += " (set SILO_URL, SILO_API_KEY and SILO_WEBHOOK_SECRET in SubExtractor)"
	}
	return message, nil
}

func (c *connectionChecker) fetchVersion(ctx context.Context, client *http.Client, base string) string {
	status, body, err := probeGet(ctx, client, base+infoProbePath, "")
	if err != nil || status < 200 || status >= 300 {
		return ""
	}
	return parseVersion(body)
}

// probeGet performs a GET with the given API key (Bearer) and returns the
// status code plus a bounded body.
func probeGet(ctx context.Context, client *http.Client, endpoint, apiKey string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	return resp.StatusCode, body, nil
}

// parseSiloStatus reads the configured/enabled flags from /api/silo/status.
func parseSiloStatus(body []byte) (configured, enabled bool) {
	var payload struct {
		Configured *bool `json:"configured"`
		Enabled    *bool `json:"enabled"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		if payload.Configured != nil {
			configured = *payload.Configured
		}
		if payload.Enabled != nil {
			enabled = *payload.Enabled
		}
	}
	return configured, enabled
}

func parseVersion(body []byte) string {
	var payload struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		return strings.TrimSpace(payload.Version)
	}
	return ""
}
