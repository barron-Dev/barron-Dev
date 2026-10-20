# Dark-web research dataset intake assessment

Status: research/staging only. This document does not register a production source, assert live coverage, or authorize operational use against a person or organization.

## 1. Tor dark-market ecosystem graph archive

### Observed structure
The supplied GraphML archive was parsed locally. The archive README describes a graph assembled from material collected July–November 2024, with identity-like entities extracted from pages and identity values reportedly anonymized. The actual graph still contains identity-linked values, so treat the graph as sensitive and do not commit or upload it to the repository.

Observed graph counts:
- 139,356 total nodes
- 82,285 service/page nodes
- 57,071 identity-type nodes
- 248,791 edges in the parsed GraphML; the README claims 248,971 (180-edge discrepancy requiring provenance reconciliation)
- The 82,285 page/service nodes are not 82,285 unique hosts: only 39 distinct domain values were observed in the domain field
- All service/page nodes were labeled `malicious` in the supplied graph; this is a dataset label, not independently verified current criminality
- Service/page subcategory labels include hacking, finance-crypto, search-engine-index, questions, drugs-narcotics, electronics, and finance
- Identity-type categories include email, Telegram URL, paste, PGP, phone, crypto wallets, Discord, and other account/service identifiers

### Safe use boundary
- Do not ingest or republish raw identity values, account handles, email addresses, phone numbers, wallet values, or graph edges that expose those values into a shared production store.
- Do not use the graph's `malicious` label as a present-day allegation or person-level verdict.
- Do not treat historical page/domain values as live onion services or current source coverage.
- A future importer may produce aggregate statistics and sanitized, independently validated source indicators only. Each indicator needs provenance, observation date, source type, confidence, validation status, and a clear historical/current distinction.
- Any person-linked case evidence must be handled through a separately authorized, access-controlled case workflow with purpose limitation, audit logging, retention rules, and legal review—not a bulk public intelligence feed.

## 2. SafeSurf Darknet 2025 traffic dataset

Published source: Mendeley Data, DOI 10.17632/kcrnj6z4rm.2, version 2. Dataset page: https://data.mendeley.com/datasets/kcrnj6z4rm/2

The publisher describes manually generated and labeled network-flow records across Tor, Freenet, I2P, ZeroNet, VPN, and normal traffic. Feature families include timestamps, flow duration, packet/byte counts, inter-arrival timing, TCP/UDP header statistics, and directional flow indicators. Behavioral classes include browsing, email, chatting, VoIP, FTP, audio/video streaming, and P2P sharing. The listed license is CC BY 4.0; preserve attribution and verify the license file packaged with any local copy before redistribution.

Published layer counts (publisher description):
- Layer 1: 360,358 Normal and 91,404 Darknet samples
- Layer 2: Freenet 26,284; ZeroNet 25,499; I2P 22,958; Tor 12,546; VPN 4,117
- Layer 3: Browsing 33,586; FTP 20,214; video streaming 9,559; P2P sharing 9,392; email 7,873; audio streaming 5,953; chatting 3,489; VoIP 1,338

These are published dataset counts, not Cyclothone detections or live coverage. The dataset describes traffic behavior; it does not claim to contain narcotics-market message text, drug listings, transaction records, or attributable criminal identities. It can be evaluated as a research benchmark for network-flow/behavior classification only. It must not be used alone to label a person, network subscriber, or organization as involved in narcotics or crime.

The supplied archive contains a nested RAR. In the current inspection environment, the RAR could be listed but not extracted, so the CSV headers, exact row counts, data types, duplicates, missing values, packaged license, and label consistency have not yet been independently verified. Do not build a production importer or train a production model until those checks are completed against the actual CSVs.

## 3. Required gates before any operational integration

1. Extract and inspect the SafeSurf CSVs in a controlled local environment; record file hashes and exact schemas without publishing raw rows.
2. Verify license/attribution files and archive provenance.
3. Build a reproducible offline validation report: row counts, schema, label distribution, nulls, duplicate rate, timestamp ranges, and leakage checks.
4. Keep research/training data separate from operational intelligence findings and customer tenant data.
5. If evaluating a classifier, split by capture/session/time to prevent leakage, report per-class precision/recall and false-positive rates, and retain model/version/evaluation evidence.
6. Never convert a traffic behavior label (for example, `chatting` or `Tor`) into a narcotics finding. A narcotics-related finding requires independently corroborated, lawful, target-relevant evidence.
7. Keep current source checks distinct from historical research records. A candidate, a dataset label, and a source catalog entry do not count as a live check.
8. No production writes, migrations, worker enablement, deployment, customer alerting, or law-enforcement export are included in this staging work.

## 4. Citation

Al-Syouf, I. A.; Obaidat, M. J.; Masa’deh, A. E.; Awawdeh, Y. F.; Abu Al-Haija, Q. *A Novel Dataset for Multiclass Detection and Classification of Darknet Traffic (SafeSurf Darknet 2025).* Mendeley Data, version 2, published 24 July 2025. DOI: 10.17632/kcrnj6z4rm.2. CC BY 4.0.
