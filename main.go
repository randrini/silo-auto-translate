package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	pb "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimedefault"
	"github.com/hashicorp/go-hclog"
)

// configKey is the global_config_schema entry key that carries the
// SubExtractor connection settings (subextractor_url, subextractor_api_key,
// webhook_secret).
const configKey = "subextractor"

//go:embed manifest.json
var manifestJSON []byte

// runtimeServer implements the Runtime capability. It embeds
// runtimedefault.Server so BindHostBroker is handled for us; the host calls
// Configure with the plugin's global config, which we keep in memory for the
// webhook routes to consume.
type runtimeServer struct {
	runtimedefault.Server
	configMu sync.Mutex
	config   *pluginConfig
	manifest *pb.PluginManifest
}

func (s *runtimeServer) GetManifest(context.Context, *pb.GetManifestRequest) (*pb.GetManifestResponse, error) {
	return &pb.GetManifestResponse{Manifest: s.manifest}, nil
}

func (s *runtimeServer) Configure(_ context.Context, request *pb.ConfigureRequest) (*pb.ConfigureResponse, error) {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	for _, entry := range request.GetConfig() {
		if entry.GetKey() != configKey {
			continue
		}
		values := entry.GetValue().AsMap()
		cfg := &pluginConfig{
			SubextractorURL:    stringValue(values["subextractor_url"]),
			SubextractorAPIKey: stringValue(values["subextractor_api_key"]),
			WebhookSecret:      stringValue(values["webhook_secret"]),
		}
		secrets, err := parseWebhookSecrets(values["webhook_secrets"])
		if err != nil {
			return nil, err
		}
		cfg.WebhookSecrets = secrets
		if cfg.SubextractorURL == "" || cfg.SubextractorAPIKey == "" || cfg.WebhookSecret == "" {
			// Accept an empty configure so the plugin starts and the admin
			// page can show "not configured". The webhook route rejects
			// deliveries until all three values are present.
			s.config = nil
			return &pb.ConfigureResponse{}, nil
		}
		s.config = cfg
		return &pb.ConfigureResponse{}, nil
	}
	// No subextractor config entry yet — accept so the plugin starts.
	s.config = nil
	return &pb.ConfigureResponse{}, nil
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// parseWebhookSecrets decodes the optional webhook_secrets config value: a
// JSON object mapping secret id → secret (e.g. {"subex": "whsec_..."}).
// Returns nil when the value is absent or empty.
func parseWebhookSecrets(v any) (map[string]string, error) {
	if v == nil {
		return nil, nil
	}
	var raw string
	switch t := v.(type) {
	case string:
		raw = strings.TrimSpace(t)
	case map[string]any:
		// The host may deliver the textarea value as a decoded object.
		out := make(map[string]string, len(t))
		for k, val := range t {
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("webhook_secrets: value for %q must be a string", k)
			}
			out[k] = s
		}
		return out, nil
	default:
		return nil, fmt.Errorf("webhook_secrets: must be a JSON object string")
	}
	if raw == "" {
		return nil, nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("webhook_secrets: invalid JSON object: %w", err)
	}
	for id, secret := range out {
		if strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("webhook_secrets: secret id must not be empty")
		}
		if strings.TrimSpace(secret) == "" {
			return nil, fmt.Errorf("webhook_secrets: secret for id %q must not be empty", id)
		}
	}
	return out, nil
}

func main() {
	manifest, err := loadManifest()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load manifest: %v\n", err)
		os.Exit(1)
	}

	runtime := &runtimeServer{manifest: manifest}
	routes := newWebhookRoutes(runtime)

	sdkruntime.Serve(sdkruntime.ServeConfig{
		Logger: hclog.New(&hclog.LoggerOptions{Name: "silo-auto-translate"}),
		Servers: sdkruntime.CapabilityServers{
			Runtime:    runtime,
			HttpRoutes: routes,
		},
	})
}

func loadManifest() (*pb.PluginManifest, error) {
	manifest, err := publicmanifest.Load(manifestJSON)
	if err != nil {
		return nil, err
	}
	if manifest.Checksum == "" {
		executable, err := os.Executable()
		if err == nil {
			if binary, err := os.ReadFile(executable); err == nil {
				checksum := sha256.Sum256(binary)
				manifest.Checksum = hex.EncodeToString(checksum[:])
			}
		}
	}
	return manifest, nil
}
