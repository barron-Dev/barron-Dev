# Telegram Source Inventory vs Runtime Defaults — Reconciliation

> Read-only comparison of the current scheduler defaults against the attributed upstream catalog. This report does not activate, remove, or change any source.

- Compared on 2026-10-10.
- Catalog: [telegram-public-handle-inventory.md](telegram-public-handle-inventory.md).
- Scheduler source: [scheduler.py](../../src/cyclothone/darkweb/scheduler.py).
- Customer request worker: [request_worker.py](../../src/cyclothone/darkweb/request_worker.py).

## Findings

- Scheduler defaults: **25**.
- Defaults listed upstream as ONLINE: **5**.
- Defaults listed upstream as OFFLINE: **10**.
- Defaults absent from this catalog: **10**.
- Upstream ONLINE/OFFLINE labels are not a live check and are not proof that a channel is suitable or safe to monitor.

| Configured handle | Upstream label | Upstream status |
|---|---|---|
| `gladdos69_official` | DDoS | ONLINE |
| `arvin_club` | — | OFFLINE |
| `cveNotify` | CVE Feed | ONLINE |
| `bugatti_cloud` | Bugatti Cloud Redline Stealer | OFFLINE |
| `joker_reborn` | Joker Reborn Redline Stealer | OFFLINE |
| `ObserverCloud` | Observer Cloud Redline Stealer (Harvests other channels) | OFFLINE |
| `darkstormteambackup2` | Dark Storm Team | OFFLINE |
| `snatch_info` | Snatch ransomware gang | ONLINE |
| `bl00dy_Ransomware_Gang` | Bl00dy ransomware gang | OFFLINE |
| `Stormous` | — | NOT_IN_CATALOG |
| `Openbullet` | — | NOT_IN_CATALOG |
| `Forum` | — | NOT_IN_CATALOG |
| `AresLoader` | — | NOT_IN_CATALOG |
| `opendataleaks` | Data Leaks | OFFLINE |
| `baseleak` | Data Leaks | OFFLINE |
| `NullLeak` | Data Leaks | OFFLINE |
| `DWI_OFFICIAL` | — | OFFLINE |
| `DarkfeedNews` | News | ONLINE |
| `txtbaseslog` | — | NOT_IN_CATALOG |
| `Developer_Astra` | — | NOT_IN_CATALOG |
| `darkside_hubb` | — | NOT_IN_CATALOG |
| `TXT_LOG_ALIEN` | — | NOT_IN_CATALOG |
| `LeakBase` | — | NOT_IN_CATALOG |
| `CodeBreachLab` | — | NOT_IN_CATALOG |
| `ExploitService` | Exploit Service | ONLINE |

## Request-path safety boundary

- Both paths now use the shared resolver in `telegram_config.py`.
- The continuous scheduler retains the 25 legacy candidates for its existing polling path.
- Customer-triggered scans use `configured_telegram_channels(use_defaults=False)`: if neither environment variable is set, Telegram is marked unavailable instead of silently enabling unverified candidates.
- This is intentional fail-closed behavior. Configure only handles that have been checked for current public reachability; the upstream ONLINE/OFFLINE labels are not enough.

## Safe next action

- Recover and reconcile the separate user-provided 1,031-record inventory; it has not yet been recovered in full.
- Keep the catalog separate from active monitoring configuration; do not automatically enable all 853 upstream handles.
- Add only deliberately configured public handles and preserve per-channel checked/failed status in customer evidence.
- Do not report Telegram as checked when no channels are configured.
