# Cyclothone Dark Web source configuration

This guide documents runtime configuration for the customer-triggered Dark Web Monitoring workflow.
Never commit credential values. Add secrets through the approved secret manager and inject them at runtime.

## Source status contract

A source is not considered live merely because it is registered or enabled:
- `checked`: a provider request completed; a zero-match response is valid.
- `failed`: a configured provider request failed.
- `unavailable`: disabled, missing required credentials/configuration, or unsupported target type.
- `historical_only_archived_feed`: historical intelligence only; not live coverage.

Customer results must retain source URL, collection timestamp, match type and explicit unavailable-source reasons. Do not turn provider failures into clean/no-match claims.

## Customer request sources

| Source ID | Access | Required runtime variables | Current target support |
| --- | --- | --- | --- |
| `telegram_public` | Public Telegram web previews | `CYCLOTHONE_DW_TELEGRAM_CHANNELS` (comma-separated public channel handles) | domain, URL, email, brand, username |
| `pastebin_public` | Public Pastebin.ca feed | None | domain, URL, email |
| `bluesky_public` | Public Bluesky search API | None | domain, URL |
| `hackernews_public` | Public Hacker News search API | None | domain, URL |
| `lemmy_public` | Public Lemmy instance search API | None | domain, URL |
| `reddit_public` | Reddit OAuth search API | `CYCLOTHONE_REDDIT_CLIENT_ID`, `CYCLOTHONE_REDDIT_CLIENT_SECRET` | domain, URL |
| `github_code` | GitHub code search API | `CYCLOTHONE_GITHUB_TOKEN` | domain, URL |
| `ransomwatch` | Archived public corpus | None | historical-only; excluded from live coverage |

HIBP is not part of the intended source set. Do not add an HIBP key.

## Initial source-key checklist

- [ ] Confirm `CYCLOTHONE_DW_TELEGRAM_CHANNELS` contains public channels approved for monitoring.
- [ ] Add `CYCLOTHONE_GITHUB_TOKEN` through the secret manager if GitHub code search is authorized for the account.
- [ ] Register a Reddit application and add `CYCLOTHONE_REDDIT_CLIENT_ID` and `CYCLOTHONE_REDDIT_CLIENT_SECRET` through the secret manager.
- [ ] Do not add X/Meta credentials until a supported connector and the required platform permissions are implemented.
- [ ] After the migration is reviewed and applied and the code is deployed, run a customer-targeted request and inspect per-source outcomes and evidence.

## Safety and evidence rules

Only use public or explicitly authorized sources. Never collect private messages or private communities without authorization. Do not persist plaintext passwords or secret values. An unavailable source is a coverage gap, not a clean result. A successful query with no exact target match must be reported separately from a failed query.
