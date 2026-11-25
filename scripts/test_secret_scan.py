import unittest

from scripts.secret_scan import findings_for_text


class SecretScanTests(unittest.TestCase):
    def test_loopback_ci_database_url_is_a_test_fixture(self):
        self.assertEqual(
            findings_for_text(
                ".github/workflows/ci.yml",
                "TEST_DATABASE_URL=postgres://postgres:test-password@127.0.0.1:5432/postgres",
            ),
            [],
        )

    def test_non_loopback_database_url_is_still_reported(self):
        self.assertEqual(
            findings_for_text(
                ".github/workflows/ci.yml",
                "TEST_DATABASE_URL=postgres://postgres:test-password@db.example.com:5432/postgres",
            ),
            [(".github/workflows/ci.yml", "TEST_DATABASE_URL")],
        )

    def test_test_word_does_not_exempt_non_ci_passwords(self):
        self.assertEqual(
            findings_for_text("env/api.env", "DATABASE_PASSWORD=production-test-password-value"),
            [("env/api.env", "DATABASE_PASSWORD")],
        )


if __name__ == "__main__":
    unittest.main()
