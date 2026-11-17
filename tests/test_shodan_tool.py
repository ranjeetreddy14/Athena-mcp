import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add parent to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import shodan_tool
from fixture_replay import load_fixture

FIXTURE = {c['label']: c for c in load_fixture('shodan')['cases']}

class TestShodanTool(unittest.TestCase):
    def test_validate_ip_public(self):
        self.assertTrue(shodan_tool.validate_ip("8.8.8.8"))
        self.assertTrue(shodan_tool.validate_ip("1.1.1.1"))

    def test_validate_ip_private(self):
        self.assertFalse(shodan_tool.validate_ip("192.168.1.1"))
        self.assertFalse(shodan_tool.validate_ip("10.0.0.1"))
        self.assertFalse(shodan_tool.validate_ip("127.0.0.1"))
        self.assertFalse(shodan_tool.validate_ip("invalid-ip"))

    @patch('tools.shodan_tool.os.getenv')
    def test_missing_api_key(self, mock_getenv):
        mock_getenv.return_value = None
        result = shodan_tool.execute("8.8.8.8")
        self.assertIn("error", result)
        self.assertIn("Missing SHODAN_API_KEY", result["error"])

    @patch('tools.shodan_tool.os.getenv')
    @patch('tools.shodan_tool.requests.get')
    def test_execute_success(self, mock_get, mock_getenv):
        """Recorded Shodan response for 8.8.8.8 (fixtures/shodan.json, 'benign')."""
        mock_getenv.return_value = "dummy_key"
        case = FIXTURE["benign"]
        raw = case["response"]["json"]
        mock_resp = MagicMock()
        mock_resp.status_code = case["response"]["status_code"]
        mock_resp.json.return_value = raw
        mock_get.return_value = mock_resp

        result = shodan_tool.execute(case["indicator"])

        # Verify Normalization
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["country"], raw["country_name"])
        self.assertEqual(result["ports"], raw["ports"])
        self.assertNotIn("error", result)
        self.assertEqual(mock_get.call_args.args[0], case["request"]["url"])

    @patch('tools.shodan_tool.os.getenv')
    @patch('tools.shodan_tool.requests.get')
    def test_execute_404(self, mock_get, mock_getenv):
        """Recorded Shodan 404 for a ThreatFox-listed C2 IP (fixtures/shodan.json, 'malicious')."""
        mock_getenv.return_value = "dummy_key"
        case = FIXTURE["malicious"]
        mock_resp = MagicMock()
        mock_resp.status_code = case["response"]["status_code"]
        mock_resp.json.return_value = case["response"]["json"]
        mock_get.return_value = mock_resp

        result = shodan_tool.execute(case["indicator"])
        self.assertEqual(result["status"], "not_found")

if __name__ == '__main__':
    unittest.main()
