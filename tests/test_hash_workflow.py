import unittest
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
from server import handle_call_tool
from orchestrator.entity import detect_entity, EntityType

class TestHashWorkflow(unittest.IsolatedAsyncioTestCase):
    @patch('tools.threatfox_tool.execute')
    @patch('server.detect_entity')
    async def test_hash_prioritizes_threatfox(self, mock_detect, mock_tf_exec):
        """Test that HASH entities default to ThreatFox first."""
        # Bottom-Up: 1st arg is closest decorator (detect_entity)
        mock_detect.return_value = SimpleNamespace(type=EntityType.HASH, value="abc123hash")
        mock_tf_exec.return_value = {"malware_family": "Emotet", "confidence": 100}
        
        args = {"query": "check hash abc123hash"}
        resp_json = await handle_call_tool("ti_query", args)
        
        data = json.loads(resp_json[0].text)
        self.assertEqual(data["audit"]["tool"], "threatfox_ioc")
        self.assertTrue(data["ok"])

    @patch('tools.threatfox_tool.execute')
    @patch('server.detect_entity')
    async def test_hash_fallback_suggestion(self, mock_detect, mock_tf_exec):
        """Test that HASH entities suggest VirusTotal if ThreatFox has no results."""
        mock_detect.return_value = SimpleNamespace(type=EntityType.HASH, value="abc123hash")
        mock_tf_exec.return_value = {"status": "no_result", "message": "Not found"}
        
        args = {"query": "check hash abc123hash"}
        resp_json = await handle_call_tool("ti_query", args)
        
        data = json.loads(resp_json[0].text)
        self.assertFalse(data["ok"])
        self.assertIn("Would you like to perform a deeper scan on VirusTotal", data["suggestions"][0])

    @patch('tools.virustotal_tool.execute')
    @patch('server.detect_entity')
    async def test_hash_explicit_vt_request(self, mock_detect, mock_vt_exec):
        """Test that HASH entities trigger VirusTotal if explicitly requested."""
        mock_detect.return_value = SimpleNamespace(type=EntityType.HASH, value="abc123hash")
        mock_vt_exec.return_value = {"verdict": "malicious"}
        
        args = {"query": "yes check this hash on virustotal abc123hash"}
        resp_json = await handle_call_tool("ti_query", args)
        
        data = json.loads(resp_json[0].text)
        self.assertEqual(data["audit"]["tool"], "url_scan_virustotal")
        self.assertTrue(data["ok"])

if __name__ == '__main__':
    unittest.main()
