package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
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
