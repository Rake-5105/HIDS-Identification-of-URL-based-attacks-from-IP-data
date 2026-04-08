import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER_UTILS = ROOT / "hids-dashboard" / "server" / "utils"
sys.path.insert(0, str(SERVER_UTILS))

from module_pipeline_runner import _infer_attack_outcome


class AttackOutcomeIndicatorTests(unittest.TestCase):
    def test_sql_injection_success(self):
        result = _infer_attack_outcome("SQL Injection", 200, response_body="Welcome admin")
        self.assertEqual(result, "confirmed_success")

    def test_xss_success(self):
        result = _infer_attack_outcome("XSS", 200, response_body="<script>alert(1)</script>")
        self.assertEqual(result, "confirmed_success")

    def test_lfi_success(self):
        result = _infer_attack_outcome("Local File Inclusion", 200, response_body="root:x:0:0:root:/root:/bin/bash")
        self.assertEqual(result, "confirmed_success")

    def test_rfi_success(self):
        result = _infer_attack_outcome("Remote File Inclusion", 200, response_body="shell prompt ready")
        self.assertEqual(result, "confirmed_success")

    def test_command_injection_success(self):
        result = _infer_attack_outcome("Command Injection", 200, response_body="uid=33(www-data) gid=33(www-data)")
        self.assertEqual(result, "confirmed_success")

    def test_ssrf_success(self):
        result = _infer_attack_outcome("Server-Side Request Forgery", 200, response_body="internal server admin panel")
        self.assertEqual(result, "confirmed_success")

    def test_ldap_injection_success(self):
        result = _infer_attack_outcome("LDAP Injection", 200, response_body="login success")
        self.assertEqual(result, "confirmed_success")

    def test_header_injection_success(self):
        result = _infer_attack_outcome("Header Injection", 200, response_headers="Set-Cookie: auth=1")
        self.assertEqual(result, "confirmed_success")

    def test_brute_force_success(self):
        result = _infer_attack_outcome("Brute Force", 200, response_body="login success")
        self.assertEqual(result, "confirmed_success")

    def test_dos_success(self):
        result = _infer_attack_outcome("Denial of Service", 200, response_time=5001, threshold_ms=3000)
        self.assertEqual(result, "confirmed_success")

    def test_csrf_success(self):
        result = _infer_attack_outcome("CSRF", 200, response_body="transaction successful")
        self.assertEqual(result, "confirmed_success")

    def test_no_response_defaults_to_attempt(self):
        result = _infer_attack_outcome(
            "SQL Injection",
            None,
            url_value="/login",
            payload_value="' OR 1=1 --",
            response_body="",
            response_headers="",
            response_time=None,
        )
        self.assertEqual(result, "attempt")


if __name__ == "__main__":
    unittest.main()