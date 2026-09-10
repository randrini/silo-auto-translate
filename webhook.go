package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/hashicorp/go-hclog"
)

const (
	statusPath         = "/status"
	webhookPath        = "/webhook"
	adminPagePath      = "/admin/auto-translate"
	adminRoleHeader    = "X-Silo-User-Role"
	maxWebhookBody     = 1 << 20 // 1 MiB
	signatureMaxAge    = 300 * time.Second
	subextractorTimeout = 1800 * time.Second
)

// pluginConfig is the in-memory SubExtractor connection settings.
type pluginConfig struct {
	SubextractorURL    string
	SubextractorAPIKey string
	WebhookSecret      string
	// WebhookSecrets maps a secret id to a webhook secret for multiple silo
	// webhook registrations. Entries take precedence over WebhookSecret for
	// matching ids; WebhookSecret acts as the "default" id.
	WebhookSecrets map[string]string
}

// secretFor resolves the webhook secret for a signature id. The "default" id
// maps to WebhookSecret; webhook_secrets entries override it for matching ids.
func (c *pluginConfig) secretFor(id string) (string, bool) {
	if id == "" {
		return "", false
	}
	if c.WebhookSecrets != nil {
		if s, ok := c.WebhookSecrets[id]; ok && strings.TrimSpace(s) != "" {
			return s, true
		}
	}
	if id == "default" && strings.TrimSpace(c.WebhookSecret) != "" {
		return c.WebhookSecret, true
	}
	return "", false
}

// webhookPayload is the rating.set delivery body sent by silo's notification
// system. Only type == "rating.set" with a non-empty rating.item_id triggers
// processing; anything else is ignored.
type webhookPayload struct {
	Type      string `json:"type"`
	Rating    struct {
		Rating float64 `json:"rating"`
		ItemID string  `json:"item_id"`
	} `json:"rating"`
	Series *struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	} `json:"series"`
	Episode   *json.RawMessage `json:"episode"`
	ProfileID any              `json:"profile_id"`
}

// subextractorRequest is the body POSTed to SubExtractor's /api/silo/process.
type subextractorRequest struct {
	ItemID string `json:"item_id"`
	Title  string `json:"title"`
}

// webhookRoutes implements the http_routes.v1 capability. The host proxies
// requests to Handle with the declared route path (e.g. "/webhook") and
// forwards the original headers.
type webhookRoutes struct {
	pb.UnimplementedHttpRoutesServer
	server *runtimeServer
	logger hclog.Logger

	inflightMu sync.Mutex
	inflight   map[string]struct{}
}

func newWebhookRoutes(server *runtimeServer) *webhookRoutes {
	return &webhookRoutes{
		server:   server,
		logger:   hclog.New(&hclog.LoggerOptions{Name: "silo-auto-translate-webhook"}),
		inflight: make(map[string]struct{}),
	}
}

func (w *webhookRoutes) Handle(ctx context.Context, req *pb.HandleHTTPRequest) (*pb.HandleHTTPResponse, error) {
	if req == nil {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "bad request"})
	}
	path := strings.TrimRight(req.GetPath(), "/")
	method := strings.ToUpper(req.GetMethod())

	switch {
	case path == statusPath && method == http.MethodGet:
		return w.handleStatus(req)
	case path == adminPagePath && method == http.MethodGet:
		return w.handleAdminPage(req)
	case path == webhookPath && method == http.MethodPost:
		// Exact /webhook without signature tokens: fail fast and visibly so
		// misconfiguration is noticed instead of silently succeeding.
		return jsonResponse(http.StatusBadRequest, map[string]string{
			"error": "missing signature token",
			"hint":  "use /webhook/sig:<secretId>/ts:<epoch>",
		})
	case strings.HasPrefix(path, webhookPath+"/") && method == http.MethodPost:
		return w.handleWebhook(ctx, req)
	default:
		return jsonResponse(http.StatusNotFound, map[string]string{"error": "route not found"})
	}
}

// handleStatus serves GET /status (admin only): version and configured state.
func (w *webhookRoutes) handleStatus(req *pb.HandleHTTPRequest) (*pb.HandleHTTPResponse, error) {
	if !isAdmin(req) {
		return jsonResponse(http.StatusForbidden, map[string]string{"error": "admin access required"})
	}
	cfg := w.currentConfig()
	return jsonResponse(http.StatusOK, map[string]any{
		"version":    "0.1.1",
		"configured": cfg != nil,
	})
}

// handleAdminPage serves GET /admin/auto-translate (admin only): a small
// self-contained page showing the configured state and the exact webhook URL
// computed from the current location.
func (w *webhookRoutes) handleAdminPage(req *pb.HandleHTTPRequest) (*pb.HandleHTTPResponse, error) {
	if !isAdmin(req) {
		return jsonResponse(http.StatusForbidden, map[string]string{"error": "admin access required"})
	}
	cfg := w.currentConfig()
	configured := cfg != nil
	body := []byte(fmt.Sprintf(adminPageHTML, map[bool]string{true: "Configured", false: "Not configured"}[configured]))
	return &pb.HandleHTTPResponse{
		StatusCode: http.StatusOK,
		Body:       body,
		Headers: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
			"Cache-Control": "no-store",
		},
	}, nil
}

// handleWebhook serves POST /webhook/* (public). The signature components
// ride in the path — silo's plugin proxy forwards only a fixed header
// whitelist and drops X-Silo-Signature, so the HMAC inputs are carried as
// /webhook/sig:<secretId>/ts:<epoch>/v1:<hex>. The HMAC still covers
// "<epoch>.<body>" (silo signs only the body, never the URL), so path
// rewriting is safe. It verifies synchronously, parses the payload, dedupes
// by item_id, then kicks off the SubExtractor call in a goroutine and ACKs
// fast.
func (w *webhookRoutes) handleWebhook(ctx context.Context, req *pb.HandleHTTPRequest) (*pb.HandleHTTPResponse, error) {
	cfg := w.currentConfig()
	if cfg == nil {
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "plugin is not configured"})
	}
	if len(req.GetBody()) > maxWebhookBody {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "body too large"})
	}
	secretID, epoch, claimed, err := parseSignaturePath(req.GetPath())
	if err != nil {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	secret, ok := cfg.secretFor(secretID)
	if !ok {
		return jsonResponse(http.StatusUnauthorized, map[string]string{"error": "unknown signature id"})
	}
	if !verifySignature(secret, req.GetBody(), epoch, claimed) {
		return jsonResponse(http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
	}
	payload, err := parsePayload(req.GetBody())
	if err != nil {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid payload"})
	}
	if payload.Type != "rating.set" || strings.TrimSpace(payload.Rating.ItemID) == "" {
		return jsonResponse(http.StatusOK, map[string]string{"status": "ignored"})
	}
	itemID := strings.TrimSpace(payload.Rating.ItemID)
	if !w.beginInflight(itemID) {
		return jsonResponse(http.StatusOK, map[string]any{"status": "accepted", "item_id": itemID, "deduplicated": true})
	}
	title := itemID
	if payload.Series != nil && strings.TrimSpace(payload.Series.Title) != "" {
		title = strings.TrimSpace(payload.Series.Title)
	}
	go w.processAsync(cfg, itemID, title)
	return jsonResponse(http.StatusOK, map[string]string{"status": "accepted", "item_id": itemID})
}

// parseSignaturePath extracts the secret id, signed epoch, and claimed HMAC
// digest from a webhook path of the form
// /webhook/sig:<secretId>/ts:<epoch>/v1:<hex>. Extra segments are tolerated;
// any missing or malformed token yields a clear 4xx error.
func parseSignaturePath(path string) (secretID string, epoch int64, claimed string, err error) {
	rest := strings.TrimPrefix(strings.TrimRight(path, "/"), webhookPath+"/")
	segments := strings.Split(rest, "/")
	var secretIDRaw, epochRaw, claimedRaw string
	for _, seg := range segments {
		switch {
		case strings.HasPrefix(seg, "sig:"):
			secretIDRaw = strings.TrimPrefix(seg, "sig:")
		case strings.HasPrefix(seg, "ts:"):
			epochRaw = strings.TrimPrefix(seg, "ts:")
		case strings.HasPrefix(seg, "v1:"):
			claimedRaw = strings.TrimPrefix(seg, "v1:")
		}
	}
	if secretIDRaw == "" {
		return "", 0, "", errors.New("missing signature token")
	}
	if epochRaw == "" {
		return "", 0, "", errors.New("missing timestamp token")
	}
	if claimedRaw == "" {
		return "", 0, "", errors.New("missing signature digest")
	}
	epoch, err = strconv.ParseInt(epochRaw, 10, 64)
	if err != nil || epoch <= 0 {
		return "", 0, "", errors.New("invalid timestamp token")
	}
	if len(claimedRaw) != 64 {
		return "", 0, "", errors.New("invalid signature digest")
	}
	if _, err := hex.DecodeString(claimedRaw); err != nil {
		return "", 0, "", errors.New("invalid signature digest")
	}
	return secretIDRaw, epoch, strings.ToLower(claimedRaw), nil
}

// processAsync POSTs the item to SubExtractor's /api/silo/process and logs
// the outcome. It runs in a goroutine so the webhook ACK is never blocked by
// the (potentially ~30 minute) pipeline.
func (w *webhookRoutes) processAsync(cfg *pluginConfig, itemID, title string) {
	defer w.endInflight(itemID)
	started := time.Now()
	err := w.callSubextractor(cfg, itemID, title)
	if err != nil {
		w.logger.Error("subextractor process failed",
			"item_id", itemID, "title", title,
			"duration_ms", time.Since(started).Milliseconds(), "error", err.Error())
		return
	}
	w.logger.Info("subextractor process completed",
		"item_id", itemID, "title", title,
		"duration_ms", time.Since(started).Milliseconds())
}

// callSubextractor performs the outbound POST using net/http directly (the
// SDK httpclient hardcodes X-Api-Key, which is not the SubExtractor auth
// scheme). HTTP is allowed only for private/local hosts, mirroring the
// reference plugin's allow-http-for-private-hosts policy.
func (w *webhookRoutes) callSubextractor(cfg *pluginConfig, itemID, title string) error {
	endpoint, err := subextractorEndpoint(cfg.SubextractorURL)
	if err != nil {
		return err
	}
	body, err := json.Marshal(subextractorRequest{ItemID: itemID, Title: title})
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), subextractorTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.SubextractorAPIKey)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: subextractorTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request subextractor failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("subextractor returned status %d", resp.StatusCode)
	}
	return nil
}

// subextractorEndpoint validates the configured URL and enforces the
// private-host policy for plain HTTP.
func subextractorEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("a valid SubExtractor URL is required (http or https)")
	}
	if u.Scheme == "http" && !isPrivateHost(u.Hostname()) {
		return "", errors.New("insecure HTTP is allowed only for private/local SubExtractor hosts")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/silo/process"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// isPrivateHost mirrors the reference plugin's policy: localhost, .local
// suffixes, single-label Docker/service names, and private IPs are private.
func isPrivateHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" || strings.HasSuffix(host, ".local") || !strings.Contains(host, ".") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	return false
}

// verifySignature checks an HMAC over "<epoch>.<body>" using the Stripe
// convention v1 = hex(hmac_sha256(secret, "<epoch>.<body>")). The epoch is
// the signed timestamp carried in the path; it must be within
// signatureMaxAge of now. claimed is the hex digest from the path.
func verifySignature(secret string, body []byte, epoch int64, claimed string) bool {
	if secret == "" || epoch <= 0 || len(claimed) != 64 {
		return false
	}
	now := time.Now().Unix()
	if now-epoch > int64(signatureMaxAge.Seconds()) || epoch-now > int64(signatureMaxAge.Seconds()) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(epoch, 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(claimed)))
}

// parsePayload decodes the webhook body into a typed struct.
func parsePayload(body []byte) (*webhookPayload, error) {
	var payload webhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// beginInflight atomically marks itemID as processing. Returns false if it
// was already in flight.
func (w *webhookRoutes) beginInflight(itemID string) bool {
	w.inflightMu.Lock()
	defer w.inflightMu.Unlock()
	if _, ok := w.inflight[itemID]; ok {
		return false
	}
	w.inflight[itemID] = struct{}{}
	return true
}

func (w *webhookRoutes) endInflight(itemID string) {
	w.inflightMu.Lock()
	defer w.inflightMu.Unlock()
	delete(w.inflight, itemID)
}

func (w *webhookRoutes) currentConfig() *pluginConfig {
	w.server.configMu.Lock()
	defer w.server.configMu.Unlock()
	return w.server.config
}

func isAdmin(req *pb.HandleHTTPRequest) bool {
	return strings.EqualFold(req.GetHeaders()[adminRoleHeader], "admin")
}

func jsonResponse(status int, payload any) (*pb.HandleHTTPResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &pb.HandleHTTPResponse{
		StatusCode: int32(status),
		Body:       body,
		Headers: map[string]string{
			"Content-Type":  "application/json; charset=utf-8",
			"Cache-Control": "no-store",
		},
	}, nil
}

// adminPageHTML is a minimal self-contained admin page. The webhook URL is
// computed in JS from the current location so it works regardless of the
// installation id in the mount path.
const adminPageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Auto Translate · Silo</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; background: #0f1115; color: #e6e8eb; }
  .wrap { max-width: 720px; margin: 0 auto; padding: 40px 20px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .eyebrow { color: #8b93a1; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
  .card { background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 20px; margin-top: 20px; }
  .row { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #22262f; }
  .row:last-child { border-bottom: 0; }
  .label { color: #8b93a1; font-size: 13px; }
  .ok { color: #4ade80; font-weight: 600; }
  .no { color: #f87171; font-weight: 600; }
  code { background: #0d0f13; border: 1px solid #262b36; border-radius: 6px; padding: 8px 10px; display: block; font-size: 13px; word-break: break-all; margin-top: 8px; }
  .hint { color: #8b93a1; font-size: 13px; margin-top: 8px; line-height: 1.5; }
  a { color: #60a5fa; }
</style>
</head>
<body>
<div class="wrap">
  <div class="eyebrow">Silo · Plugin</div>
  <h1>Auto Translate</h1>
  <p class="hint">Rating an item in a profile triggers a signed webhook that asks SubExtractor to extract and translate subtitles to French, then upload them back to silo.</p>
  <div class="card">
    <div class="row"><span class="label">Status</span><span id="status" class="no">%s</span></div>
    <div class="row"><span class="label">Webhook URL</span></div>
    <code id="webhook-url">…</code>
    <p class="hint">Use this URL in <b>Settings → Notifications → Webhooks</b> (enable Ratings). Silo's plugin proxy forwards only a fixed header whitelist and drops <code>X-Silo-Signature</code>, so the signature components ride in the path: <code>/webhook/sig:&lt;secretId&gt;/ts:&lt;epoch&gt;/v1:&lt;hex&gt;</code>. The <code>ts</code> segment is the signed epoch; the HMAC still validates <code>epoch.body</code>, so path rewriting is safe. Regenerate the URL when re-registering the webhook.</p>
    <p class="hint">Custom secret ids from <code>webhook_secrets</code> (e.g. <code>subex</code>) can be used in place of <code>default</code>.</p>
  </div>
</div>
<script>
  (function () {
    var m = location.pathname.match(/\/plugins\/(\d+)\//);
    var id = m ? m[1] : null;
    var el = document.getElementById('webhook-url');
    if (id) {
      var ts = Math.floor(Date.now() / 1000);
      el.textContent = location.origin + '/plugins/' + id + '/webhook/sig:default/ts:' + ts + '/v1:<hex>';
    } else {
      el.textContent = 'Unable to determine plugin installation id from ' + location.pathname;
    }
  })();
</script>
</body>
</html>
`
