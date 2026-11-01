import unittest

from bug_bounty_tool import iter_targets, missing_security_headers, normalize_target


class BugBountyToolTests(unittest.TestCase):
    def test_normalize_target_adds_https(self) -> None:
        self.assertEqual(normalize_target("example.com"), "https://example.com")

    def test_normalize_target_rejects_empty(self) -> None:
        with self.assertRaises(ValueError):
            normalize_target("   ")

    def test_missing_security_headers_detects_absent_headers(self) -> None:
        headers = {"Server": "nginx", "X-Frame-Options": "DENY"}
        missing = missing_security_headers(headers)
        self.assertIn("Content-Security-Policy", missing)
        self.assertIn("Strict-Transport-Security", missing)
        self.assertIn("X-Content-Type-Options", missing)
        self.assertNotIn("X-Frame-Options", missing)

    def test_iter_targets_reads_from_values(self) -> None:
        self.assertEqual(iter_targets(["a.com", "b.com"], None), ["a.com", "b.com"])


if __name__ == "__main__":
    unittest.main()
