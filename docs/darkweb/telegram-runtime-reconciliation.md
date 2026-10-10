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

## Request-path discrepancy

- The scheduler resolves the 25 defaults when `CYCLOTHONE_DW_TELEGRAM_CHANNELS` is unset.
- The customer request worker currently reads only `CYCLOTHONE_DW_TELEGRAM_CHANNELS` / legacy `SENTINEL_DW_TELEGRAM_CHANNELS` and treats an unset value as an empty list. Therefore the scheduler's default handles are **not automatically used by customer-triggered scans**.
- This is a code-path mismatch, not a source-availability conclusion. The customer request may correctly report `missing_channels` even while the continuous scheduler has default candidates.

## Safe next action

- Reuse one shared configuration resolver for both scheduler and request worker so the source inventory and runtime request path cannot drift.
- Keep the inventory as a catalog; do not automatically enable all 853 upstream handles.
- Before using a handle for a customer scan, validate its public preview at runtime and report per-channel checked/failed status.
- Keep offline and unknown handles out of default activation until current public reachability is established.
