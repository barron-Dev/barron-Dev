# WARC capture and hostile-content sanitizer modules

The WARC writer is offline-only and accepts raw request/response message bytes from a separately authorized capture adapter. It never performs a fetch. It uses exclusive file creation and fsync so a retry cannot silently overwrite an existing capture. The adapter must capture before content decompression and accurately document any HTTP-library header normalization. The WARC bundle must still be uploaded to immutable/versioned storage before the evidence DB row is committed.

The sanitizer emits an allowlisted HTML subset, strips active-content elements and all attributes except validated HTTP(S) anchor hrefs, and never fetches resources. It is a defensive baseline, not a substitute for a hardened isolated parser. Do not render sanitized output without a restrictive Content-Security-Policy and sandboxed viewer. PDF extraction remains a separate sandbox-only workflow and is not implemented here.

Neither module creates a database evidence row, submits an OTS/TSA request, fetches a source, or activates a worker. Those integrations require crash-recovery and conformance tests before release.
