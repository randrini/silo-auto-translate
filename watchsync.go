package main

import (
	"context"
	"strings"

	pb "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/hashicorp/go-hclog"
)

// watchSyncProvider implements the watch_sync_provider.v1 capability. The host
// uses it as a "favorite sink": when export_favorites is enabled on a watch
// sync connection, silo delivers ADD_FAVORITE events for the profile's
// favorites. We turn movie/episode favorites into the same SubExtractor call
// the rating webhook path uses, and ignore everything else.
//
// Only export_favorites is advertised (no import, no removals), so the host
// never calls the import/removal paths. The auth RPCs exist because the
// manifest contract requires an auth method; API key is the simplest one and
// simply yields a synthetic, non-expiring credential.
type watchSyncProvider struct {
	pb.UnimplementedWatchSyncProviderServer
	routes *webhookRoutes
	logger hclog.Logger
}

func newWatchSyncProvider(routes *webhookRoutes) *watchSyncProvider {
	return &watchSyncProvider{
		routes: routes,
		logger: hclog.New(&hclog.LoggerOptions{Name: "silo-auto-translate-watchsync"}),
	}
}

const (
	// watchSyncAccessToken is a synthetic credential; the host only requires a
	// non-empty access token for an API-key connection.
	watchSyncAccessToken = "silo-auto-translate"
)

func watchSyncCredentials() *pb.WatchSyncCredentials {
	return &pb.WatchSyncCredentials{
		AccessToken: watchSyncAccessToken,
		TokenType:   "Bearer",
	}
}

func watchSyncAccount() *pb.WatchSyncAccount {
	return &pb.WatchSyncAccount{
		ExternalSubject: "silo-auto-translate",
		Username:        "auto-translate",
		DisplayName:     "Silo Auto Translate",
	}
}

// ExchangeAPIKey accepts any API key the user provides when connecting the
// provider and returns a synthetic credential plus the account identity the
// host requires to persist the connection.
func (p *watchSyncProvider) ExchangeAPIKey(_ context.Context, _ *pb.WatchSyncExchangeAPIKeyRequest) (*pb.WatchSyncCredentialResponse, error) {
	return &pb.WatchSyncCredentialResponse{
		Credentials: watchSyncCredentials(),
		Account:     watchSyncAccount(),
	}, nil
}

// RefreshCredentials returns the same non-expiring synthetic credential.
func (p *watchSyncProvider) RefreshCredentials(_ context.Context, _ *pb.WatchSyncRefreshCredentialsRequest) (*pb.WatchSyncCredentialResponse, error) {
	return &pb.WatchSyncCredentialResponse{
		Credentials: watchSyncCredentials(),
		Account:     watchSyncAccount(),
	}, nil
}

func (p *watchSyncProvider) GetAccount(_ context.Context, _ *pb.WatchSyncGetAccountRequest) (*pb.WatchSyncGetAccountResponse, error) {
	return &pb.WatchSyncGetAccountResponse{Account: watchSyncAccount()}, nil
}

// ListRemoteState returns an empty authoritative snapshot. It is never called
// while only export_favorites is advertised, but returning a valid response
// keeps the provider well-formed if the host ever probes it.
func (p *watchSyncProvider) ListRemoteState(_ context.Context, _ *pb.WatchSyncListRemoteStateRequest) (*pb.WatchSyncListRemoteStateResponse, error) {
	return &pb.WatchSyncListRemoteStateResponse{CompleteSnapshot: true}, nil
}

// ApplyEvents handles the host's at-least-once event batches. Every event gets
// a result (the host treats a missing result as a retryable failure). Only
// ADD_FAVORITE for movie/episode media triggers SubExtractor; removals, series
// (UNSPECIFIED) media, and events while the plugin is disabled are ignored.
func (p *watchSyncProvider) ApplyEvents(_ context.Context, req *pb.WatchSyncApplyEventsRequest) (*pb.WatchSyncApplyEventsResponse, error) {
	resp := &pb.WatchSyncApplyEventsResponse{
		Results: make([]*pb.WatchSyncApplyResult, 0, len(req.GetEvents())),
	}
	enabled := p.routes.server.isEnabled()
	cfg := p.routes.currentConfig()

	for _, event := range req.GetEvents() {
		result := &pb.WatchSyncApplyResult{
			EventId: event.GetEventId(),
			Status:  pb.WatchSyncApplyStatus_WATCH_SYNC_APPLY_STATUS_NO_CHANGE,
		}
		resp.Results = append(resp.Results, result)

		if event.GetOperation() != pb.WatchSyncOperation_WATCH_SYNC_OPERATION_ADD_FAVORITE {
			// Favorite removals (and any future operation) are ignored.
			p.logger.Debug("watch sync operation ignored",
				"event_id", event.GetEventId(),
				"operation", event.GetOperation().String())
			continue
		}
		if !enabled {
			p.logger.Debug("favorite ignored: plugin disabled", "event_id", event.GetEventId())
			continue
		}
		media := event.GetMedia()
		if media == nil {
			p.logger.Debug("favorite ignored: missing media", "event_id", event.GetEventId())
			continue
		}
		switch media.GetMediaType() {
		case pb.WatchSyncMediaType_WATCH_SYNC_MEDIA_TYPE_MOVIE,
			pb.WatchSyncMediaType_WATCH_SYNC_MEDIA_TYPE_EPISODE:
			// Supported.
		default:
			// Series-level favorites arrive without a resolvable episode and
			// there is no series->episode resolution plugin-side.
			p.logger.Debug("favorite ignored: unsupported media type",
				"event_id", event.GetEventId(),
				"media_type", media.GetMediaType().String())
			continue
		}
		if cfg == nil {
			p.logger.Debug("favorite ignored: plugin not configured", "event_id", event.GetEventId())
			continue
		}
		itemID := strings.TrimSpace(media.GetMediaItemId())
		if itemID == "" {
			p.logger.Debug("favorite ignored: empty media item id", "event_id", event.GetEventId())
			continue
		}
		title := strings.TrimSpace(media.GetTitle())
		if title == "" {
			title = itemID
		}
		if !p.routes.beginInflight(itemID) {
			p.logger.Debug("favorite deduplicated (already in flight)", "item_id", itemID)
			result.Status = pb.WatchSyncApplyStatus_WATCH_SYNC_APPLY_STATUS_APPLIED
			continue
		}
		result.Status = pb.WatchSyncApplyStatus_WATCH_SYNC_APPLY_STATUS_APPLIED
		go p.routes.processAsync(cfg, itemID, title)
	}
	return resp, nil
}
