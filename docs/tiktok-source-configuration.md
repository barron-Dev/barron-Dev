# TikTok source configuration

Cyclothone's `tiktok_commercial` source uses TikTok's official Commercial Content API.

## Apply for access

- Developer portal: https://developers.tiktok.com/
- Commercial Content API product and application: https://developers.tiktok.com/products/commercial-content-api
- API setup guide: https://developers.tiktok.com/docs/en/commercial-content-api-getting-started
- Client access token documentation: https://developers.tiktok.com/docs/en/client-access-token-management

After TikTok approves the application, configure these **server-side Railway variables** on `cyclothone-api`:

- `CYCLOTHONE_TIKTOK_CLIENT_KEY`
- `CYCLOTHONE_TIKTOK_CLIENT_SECRET`

Do not put the client secret in chat, source control, or frontend variables. The source obtains a short-lived client token server-side for each batch.

## Coverage boundary

The Commercial Content API returns public commercial/ad-library data, currently with EU data coverage. It is not a general search API for every organic TikTok video and does not provide arbitrary creator timelines. Cyclothone reports exact matches only when the returned advertiser/video metadata contains the monitored target. Missing credentials and provider failures are reported as unavailable/failed; they are never represented as a clean scan.

For customer-authorized creator timelines, TikTok Display API requires separate user consent and the `video.list` scope; this is not the same source.
