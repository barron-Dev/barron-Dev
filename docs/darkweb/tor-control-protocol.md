# Cyclothone native Tor control protocol

## Purpose and trust boundary

The native onion collector uses Tor's authenticated ControlPort alongside the HTTP SOCKS connection. A successful HTTP response, a SOCKS proxy URL, a bootstrap status, or an HSFETCH acknowledgement alone is not sufficient to report dark-web coverage.

For each configured v3 onion seed, the collector binds the evidence to:
- the current service_request_id;
- the SHA-256 digest of the response body actually inspected;
- authenticated ControlPort and bootstrap status;
- an accepted HSFETCH and matching HS_DESC / HS_DESC_CONTENT events;
- a successful stream to that exact onion host;
- the stream's request-scoped SOCKS username;
- the circuit ID for that stream and a built HS_CLIENT_REND circuit;
- an explicitly configured IsolateSOCKSAuth option on a Tor SocksPort.

The descriptor body is not persisted. The collector stores only bounded Boolean/event summaries and a response digest. Missing or ambiguous events produce unavailable, never a successful clean result.

## Tor runtime requirements

Use a dedicated Tor process/service for Cyclothone. The API service must reach the Tor service over private networking only. Do not expose ControlPort to the public internet.

The Tor torrc must configure a SOCKS listener with explicit authentication isolation and an authenticated ControlPort. Example shape (adapt bind addresses to the private network; do not copy an open public bind):

```text
SocksPort <PRIVATE_BIND>:9050 IsolateSOCKSAuth
ControlPort <PRIVATE_BIND>:9051
HashedControlPassword <HASH_FROM_tor_--hash-password>
CookieAuthentication 0
```

Restrict network access to these ports to the Cyclothone API service. Keep the unhashed control password only in the Railway secret store. Do not put secrets in the repository or logs.

## Cyclothone API environment

Set on the API service only after the Tor service is configured:

- CYCLOTHONE_DW_TOR_CONTROL_ENABLED=true
- CYCLOTHONE_DW_TOR_CONTROL_HOST=<private Tor service hostname>
- CYCLOTHONE_DW_TOR_CONTROL_PORT=9051
- CYCLOTHONE_DW_TOR_CONTROL_PASSWORD=<Railway secret matching HashedControlPassword>
- CYCLOTHONE_DW_ONION_PROXY=socks5h://<private Tor service hostname>:9050
- CYCLOTHONE_DW_ONION_SEEDS=<reviewed comma-separated public v3 onion URLs>

The code adds a random request-scoped SOCKS username/password to the proxy URL. Tor must explicitly enable IsolateSOCKSAuth; otherwise the collector will refuse to mark route proof complete. Never put static proxy credentials in CYCLOTHONE_DW_ONION_PROXY.

## Evidence and rollout gates

1. Deploy the Tor service and configure private networking, authentication, and IsolateSOCKSAuth.
2. Upgrade the Railway API service with the branch containing TorControlProofCollector.
3. Verify the installed stem dependency and the environment variables are present without printing secret values.
4. Run a controlled, authorized customer request. Confirm a per-seed proof record binds request ID, response digest, SOCKS username, stream, and rendezvous circuit.
5. Confirm an unavailable result when any proof is missing; do not weaken the gate to make a demo appear successful.
6. Verify private evidence upload/readback and tenant-scoped result/history through authenticated end-to-end tests.

Do not use global SIGNAL NEWNYM as a substitute for per-request isolation. The collector uses read-only event subscriptions and HSFETCH; it does not modify Tor configuration at runtime. No production Tor probe is implied by this document.
