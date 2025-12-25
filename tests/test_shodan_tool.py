import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add parent to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import shodan_tool

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
        mock_getenv.return_value = "dummy_key"
        
        # Mock API Response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "country_name": "United States",
            "city": "Mountain View",
            "org": "Google LLC",
            "isp": "Google",
            "asn": "AS15169",
            "ports": [80, 443],
            "hostnames": ["dns.google"],
            "tags": ["cloud"],
            "last_update": "2023-01-01"
        }
        mock_get.return_value = mock_resp

        result = shodan_tool.execute("8.8.8.8")
        
        # Verify Normalization
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["country"], "United States")
        self.assertEqual(result["ports"], [80, 443])
        self.assertNotIn("error", result)

    @patch('tools.shodan_tool.os.getenv')
    @patch('tools.shodan_tool.requests.get')
    def test_execute_404(self, mock_get, mock_getenv):
        mock_getenv.return_value = "dummy_key"
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = shodan_tool.execute("1.2.3.4")
        self.assertEqual(result["status"], "not_found")

if __name__ == '__main__':
    unittest.main()
