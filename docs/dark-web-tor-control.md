# Native Dark Web Tor control protocol

This collector is fail-closed. A SOCKS connection or HTTP response is not Tor
protocol proof. It records only event-derived booleans and a response digest;
it does not retain HS descriptor bodies.

## Runtime configuration

Configure these only in the private Railway runtime that runs the Cyclothone API:

- `CYCLOTHONE_DW_TOR_CONTROL_ENABLED=true`
- `CYCLOTHONE_DW_TOR_CONTROL_HOST=127.0.0.1` (or a private internal Tor service hostname)
- `CYCLOTHONE_DW_TOR_CONTROL_PORT=9051`
- `CYCLOTHONE_DW_TOR_CONTROL_PASSWORD` **or** `CYCLOTHONE_DW_TOR_CONTROL_COOKIE`
- `CYCLOTHONE_DW_ONION_PROXY=socks5://127.0.0.1:9050` (or the private Tor SOCKS endpoint)
- `CYCLOTHONE_DW_ONION_SEEDS` containing only reviewed public v3 onion URLs.

Never expose the Tor ControlPort to the public internet. Prefer cookie authentication
when the Tor process and worker share a protected filesystem; otherwise use Tor's
hashed-control-password configuration with a private-only control network and store
the plaintext client password only in the platform's secret manager. Do not log
control credentials or descriptor bodies.

The collector subscribes to `HS_DESC`, `HS_DESC_CONTENT`, `STREAM`, and `CIRC`,
issues `HSFETCH` for each reviewed seed, and correlates events by onion host,
attempt start time, stream circuit ID, and built `HS_CLIENT_REND` circuit. The
proof is bound to the service request ID and SHA-256 of the inspected response.
Missing or mismatched events leave native onion coverage unavailable.

## Release gates

1. Upgrade the Railway API image so Stem is installed from `pyproject.toml`.
2. Configure the private Tor ControlPort and SOCKS endpoint.
3. Run unit tests and an authorized staging test against a reviewed public onion seed.
4. Confirm the control events are emitted by the real Tor daemon and the exact
   response digest is bound to the same request and circuit.
5. Only then should native onion be reported as checked. No production probe is
   started automatically by this code change.
