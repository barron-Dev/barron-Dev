# Native Dark Web: Honeytokens and Tor readiness

## Honeytokens

Cyclothone can generate a high-entropy `cyc-canary-` identifier for a customer
who is authorized to deploy it. The raw value is returned once by the creation
primitive. Persist only its SHA-256 digest in `dw_honeytokens`; do not put raw
tokens in logs, findings, analytics, or source metadata.

A hit is an alertable observation only after a real collector sees the exact
token in a source response and the finding plus evidence are durably persisted.
A generated token by itself is not a finding. Customers must place canaries only
in assets and workflows they own or are explicitly authorized to monitor.

The primitive and schema in this change establish safe token generation and
storage. They do not by themselves constitute a fully wired customer-facing
canary lifecycle or prove live detections.

## Tor readiness and onion seeds

The native onion collector reads:

- `CYCLOTHONE_DW_ONION_SEEDS`: comma-separated, reviewed public onion URLs.
- `CYCLOTHONE_DW_ONION_PROXY`: reachable SOCKS proxy; default
  `socks5://127.0.0.1:9050`.

The default proxy address is valid only when a Tor service is listening at that
address from the API container's network namespace. It does not provision Tor.
Do not use example or unverified onion addresses in production. Confirm route
connectivity and source reachability from the deployed API environment before
claiming the source was checked.

## Coverage semantics

No configured seeds means unavailable, not clean. An unreachable proxy or zero
reachable onion pages means unavailable/failed, not zero exposure. Report actual
page attempts and reachable sources separately. Onion crawler coverage is
bounded and is not total dark-web coverage.
