import unittest

from services.dw_discovery.url_policy import SourceOutcome, normalize_outcome, validate_candidate_url


class URLPolicyTests(unittest.TestCase):
    def test_rejects_non_http_schemes(self):
        self.assertFalse(validate_candidate_url("file:///etc/passwd", tor_configured=True).allowed)

    def test_rejects_embedded_credentials(self):
        self.assertEqual(
            validate_candidate_url("https://user:pass@example.com", tor_configured=True).reason,
            "embedded_credentials_forbidden",
        )

    def test_rejects_private_and_loopback_ips(self):
        for host in ("127.0.0.1", "10.0.0.8", "169.254.169.254", "192.168.1.2", "[::1]"):
            with self.subTest(host=host):
                self.assertFalse(validate_candidate_url(f"http://{host}/", tor_configured=True).allowed)

    def test_rejects_non_web_ports(self):
        self.assertEqual(
            validate_candidate_url("https://example.com:8443/", tor_configured=True).reason,
            "non_web_port_forbidden",
        )
        self.assertTrue(validate_candidate_url("https://example.com:443/", tor_configured=True).allowed)

    def test_onion_fails_closed_without_tor(self):
        host = "a" * 56 + ".onion"
        decision = validate_candidate_url(f"http://{host}/", tor_configured=False)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "tor_proxy_not_configured")

    def test_valid_v3_onion_requires_tor(self):
        host = "a" * 56 + ".onion"
        decision = validate_candidate_url(f"http://{host}/", tor_configured=True)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.requires_tor)

    def test_rejects_invalid_onion_length(self):
        decision = validate_candidate_url("http://" + "a" * 16 + ".onion", tor_configured=True)
        self.assertFalse(decision.allowed)

    def test_http_200_without_inspection_is_not_a_match(self):
        self.assertEqual(
            normalize_outcome(response_received=True, inspected_content=False, content_bytes=500),
            SourceOutcome.UNAVAILABLE,
        )

    def test_match_requires_inspected_content(self):
        self.assertEqual(
            normalize_outcome(response_received=True, inspected_content=True, matched=True, content_bytes=100),
            SourceOutcome.MATCHED,
        )
        self.assertEqual(
            normalize_outcome(response_received=True, inspected_content=True, matched=False, content_bytes=100),
            SourceOutcome.INSPECTED_NO_MATCH,
        )

    def test_timeout_takes_precedence(self):
        self.assertEqual(
            normalize_outcome(response_received=False, timed_out=True),
            SourceOutcome.TIMEOUT,
        )


if __name__ == "__main__":
    unittest.main()
