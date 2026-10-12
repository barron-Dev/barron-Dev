"""Unit tests for conservative public Telegram source discovery.

These tests are network-free: they validate parsing and scoring only, not source
availability or production collection.
"""
from __future__ import annotations

import unittest

from cyclothone.darkweb.source_registry import (
    classify_public_http_response,
    classify_validation,
    clean_handle,
    extract_candidates,
    merge_validation_metadata,
    validation_signals,
)


class SourceRegistryParsingTests(unittest.TestCase):
    def test_clean_handle_normalizes_public_handles(self) -> None:
        self.assertEqual(clean_handle("@Example_Channel"), "example_channel")
        self.assertIsNone(clean_handle("joinchat"))
        self.assertIsNone(clean_handle("https://t.me/example_channel"))
        self.assertIsNone(clean_handle("tiny"))

    def test_extract_candidates_only_returns_channel_handles(self) -> None:
        page = """
        <div>Forwarded from <a href="https://t.me/another_public">another</a></div>
        <div>Related: @third_public</div>
        <div>Ignore https://example.com/path and private invite links</div>
        """
        candidates = extract_candidates(page, "seed_channel")
        by_identity = {item["identity"]: item for item in candidates}
        self.assertEqual(set(by_identity), {"another_public", "third_public"})
        self.assertEqual(by_identity["another_public"]["discovered_by"], "forward")
        self.assertEqual(by_identity["third_public"]["monitoring_status"], "QUARANTINED")
        self.assertTrue(all(item["source_url"].startswith("https://t.me/") for item in candidates))

    def test_excludes_parent_and_reserved_handles(self) -> None:
        page = "https://t.me/seed_channel @joinchat https://t.me/another_public"
        candidates = extract_candidates(page, "seed_channel")
        self.assertEqual([item["identity"] for item in candidates], ["another_public"])

    def test_validation_score_is_bounded_and_only_uses_observed_signals(self) -> None:
        score, signals, messages = validation_signals("<html><body>nothing useful</body></html>")
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 10)
        self.assertEqual(score, len(signals))
        self.assertEqual(messages, 0)

    def test_connected_public_references_contribute_only_observed_evidence(self) -> None:
        score, signals, _ = validation_signals("small public page", connected_links=2)
        self.assertEqual(score, 1)
        self.assertEqual(signals, ["connected_link_network"])

    def test_http_outcomes_do_not_confuse_unknown_with_offline(self) -> None:
        self.assertEqual(classify_public_http_response(200, "public content"), ("ONLINE", "checked"))
        self.assertEqual(classify_public_http_response(200, "  "), (None, "empty_response"))
        self.assertEqual(classify_public_http_response(302, ""), (None, "redirect_not_followed"))
        self.assertEqual(classify_public_http_response(429, ""), (None, "rate_limited"))
        self.assertEqual(classify_public_http_response(503, ""), (None, "provider_error"))
        self.assertEqual(classify_public_http_response(401, ""), (None, "access_restricted"))
        self.assertEqual(classify_public_http_response(403, ""), (None, "access_restricted"))
        self.assertEqual(classify_public_http_response(404, ""), ("EXPIRED", "not_found"))

    def test_empty_page_never_scores_as_verified(self) -> None:
        score, signals, messages = validation_signals("")
        self.assertEqual((score, signals, messages), (0, [], 0))

    def test_validation_metadata_preserves_discovery_provenance(self) -> None:
        existing = {"seed_source": "operator_config", "discovery_method": "snowball", "parent": "seed_channel"}
        merged = merge_validation_metadata(existing, ["recent_activity"])
        self.assertEqual(merged["seed_source"], "operator_config")
        self.assertEqual(merged["discovery_method"], "snowball")
        self.assertEqual(merged["parent"], "seed_channel")
        self.assertEqual(merged["validation_signals"], ["recent_activity"])
        self.assertNotIn("validation_signals", existing)

    def test_absence_of_evidence_is_not_a_scam_classification(self) -> None:
        self.assertIsNone(classify_validation(0))
        self.assertIsNone(classify_validation(2))
        self.assertEqual(classify_validation(3), "LOW")
        self.assertEqual(classify_validation(5), "MEDIUM")
        self.assertEqual(classify_validation(8), "HIGH")


if __name__ == "__main__":
    unittest.main()
