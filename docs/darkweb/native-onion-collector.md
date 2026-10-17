# Native Dark Web Collector

Cyclothone's native onion collector does not require HIBP, GitHub, or another intelligence API key.

## Runtime requirements

- Run a Tor daemon/proxy reachable from the Cyclothone API container. Default SOCKS endpoint: `socks5://127.0.0.1:9050`.
- Configure a deliberately curated comma-separated list of public onion URLs in `CYCLOTHONE_DW_ONION_SEEDS`.
- Optionally set `CYCLOTHONE_DW_ONION_PROXY` to the actual Tor SOCKS endpoint.
- Install the Python SOCKS transport dependency declared in `pyproject.toml`.

Only HTTP(S) URLs whose host ends in `.onion` are accepted. Links to other public onion hosts are discovered and added to a bounded frontier; clearnet links are never followed. Newly discovered sources and per-seed reachability are persisted in the service-only `dw_onion_seeds` registry. Credentials, query strings, fragments, nonstandard ports, off-host links, redirects, and non-text responses are excluded. Crawl is bounded to 50 seeds, 20 pages per seed, 100 pages per request, and one link-following level. Page bodies are not persisted. Findings contain the exact monitored identifier, a source URL, response-body SHA-256, timestamp, and the access method.

The collector never claims a seed was checked unless at least one page returned a successful text response. It reports unavailable if no seeds are configured or no seed is reachable. A clean result means no exact match was found in the pages actually fetched—not that the entire dark web is clean.

## Deployment boundary

The migration creates the private source-seed registry, expands evidence constraints for Tor provenance and exact username/custom targets, and registers the source. It is not applied to production here. Do not deploy until a Tor route is available in the API runtime, seeds have been reviewed, and tests pass.
