# Silo Auto Translate

A [silo](https://github.com/randrini/silo-server) media-server plugin that turns profile ratings into automatic French subtitles.

When a profile rates an item, silo's notification system delivers a signed `rating.set` webhook. This plugin verifies the HMAC signature, then calls SubExtractor's `POST /api/silo/process` (API-key protected), which downloads the video from silo, extracts and translates its subtitles to French, and uploads them back.

## Flow

1. A profile rates an item in silo → silo's notification system posts a signed `rating.set` webhook to the plugin's public route (`/plugins/{id}/webhook`).
2. The plugin verifies the `X-Silo-Signature` HMAC (Stripe convention, 5-minute timestamp window), parses the payload, and dedupes by `item_id`.
3. The plugin ACKs fast (`200 {"status":"accepted"}`) and processes asynchronously: it POSTs `{"item_id": ..., "title": ...}` to SubExtractor's `/api/silo/process` with a `Bearer` API key.
4. SubExtractor downloads the video from silo, extracts and translates subtitles to French, and uploads them back to silo.

Translated FR subtitles are stored by silo as subtitle-provider subtitles in its S3/Garage storage and are tied to the media file (a `DownloadedSubtitle` row, `provider=upload`). SubExtractor's `SiloClient.upload_subtitle(media_file_id, fr_file, language="fr")` targets exactly that storage via `POST /api/v1/subtitles/upload` — no other subtitle handling is involved.

## Requirements

- **Silo fork**: this plugin relies on the outbound signed webhook delivery in the [randrini/silo-server](https://github.com/randrini/silo-server) fork (Settings → Notifications → Webhooks, with Ratings enabled).
- **SubExtractor** with the silo integration enabled. Required env vars:
  - `SILO_URL` — base URL of the silo instance.
  - `SILO_API_KEY` — silo API key used to download videos and upload subtitles.
  - `SILO_PROFILE_ID` — the silo profile whose library is processed.
  - `SILO_WEBHOOK_SECRET` — shared secret used to sign/verify webhook deliveries (must match the plugin's `webhook_secret`).
  - `SILO_AUTO_ENABLED` is **not** required for the `/api/silo/process` endpoint.

## Install

1. In silo, go to **Admin → Plugins → Catalog**.
2. Add the catalog URL:
   ```
   https://raw.githubusercontent.com/randrini/silo-auto-translate/main/catalog.json
   ```
3. Install **Silo Auto Translate** and open its admin page (Auto Translate under Admin).
4. Configure the connection:

| Setting | Value |
|---------|-------|
| `subextractor_url` | Base URL of SubExtractor, e.g. `http://subextractor:8975` (plain HTTP allowed only for private/local hosts) |
| `subextractor_api_key` | The `WEB_UI_API_KEY` of the SubExtractor instance |
| `webhook_secret` | Same value as SubExtractor's `SILO_WEBHOOK_SECRET` |

5. Copy the **webhook URL** shown on the plugin's admin page (it looks like `https://<silo>/plugins/<id>/webhook`).
6. In silo, go to **Settings → Notifications → Webhooks**, add a webhook with that URL, and enable **Ratings**.

## Routes

| Path | Method | Access | Purpose |
|------|--------|--------|---------|
| `/webhook` | POST | public | Receives signed `rating.set` deliveries; verifies HMAC, dedupes, ACKs fast, processes async |
| `/status` | GET | admin | JSON `{"version": ..., "configured": bool}` |
| `/admin/auto-translate` | GET | admin | Self-contained admin page showing status + webhook URL |

## Development

```bash
GOTOOLCHAIN=auto go mod tidy
GOTOOLCHAIN=auto go vet ./...
GOTOOLCHAIN=auto go test ./...
GOTOOLCHAIN=auto go build -o /tmp/st-check . && /tmp/st-check manifest
```

## Release

Tag a `v*` tag; the [release workflow](.github/workflows/release.yml) vets, tests, builds the three platform binaries, publishes a GitHub release with `checksums.txt`, and updates `catalog.json` on `main`.

## License

MIT — see [LICENSE](LICENSE). © randrini.
