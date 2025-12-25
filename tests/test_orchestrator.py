"""
Unit Tests for MCP Server Logic
"""
import unittest
import os
import sys

# Add parent to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator.entity import detect_entity, EntityType
from orchestrator.registry import ToolRegistry
from orchestrator.router import SemanticRouter

class TestOrchestrator(unittest.TestCase):
    def setUp(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        registry_path = os.path.join(base_dir, 'registry', 'tools.json')
        self.registry = ToolRegistry(registry_path)
        self.router = SemanticRouter(self.registry)

    def test_entity_detection(self):
        # IP
        self.assertEqual(detect_entity("8.8.8.8").type, EntityType.IP)
        self.assertEqual(detect_entity("Check 8.8.8.8 now").type, EntityType.IP)
        
        # URL (Higher precedence than Domain)
        self.assertEqual(detect_entity("https://google.com").type, EntityType.URL)
        
        # Domain
        self.assertEqual(detect_entity("google.com").type, EntityType.DOMAIN)
        
        # Unknown
        self.assertEqual(detect_entity("Hello world").type, EntityType.UNKNOWN)

    def test_router_shodan(self):
        query = "Where is 8.8.8.8 located?"
        entity = detect_entity(query)
        result = self.router.route_query(query, entity)
        
        self.assertEqual(result.tool_name, "ip_intel_shodan")
        self.assertTrue(result.confidence > 0.30)

    def test_router_virustotal(self):
        query = "Scan https://malicious-site.com/login"
        entity = detect_entity(query)
        result = self.router.route_query(query, entity)
        
        self.assertEqual(result.tool_name, "url_scan_virustotal")
        self.assertTrue(result.confidence > 0.30)

    def test_router_type_mismatch(self):
        # Query asking for URL scan but providing an IP entity
        # Should fail Layer A (Entity Filter)
        query = "Scan this url" 
        # But we force Detection to look like IP to test filter
        from orchestrator.entity import DetectedEntity
        entity = DetectedEntity(EntityType.IP, "1.1.1.1")
        
        # Router should NOT pick VT because VT input_type is 'url'
        result = self.router.route_query(query, entity)
        
        # Should pick Shodan (because it accepts IP) or fail if semantic match is low
        # But crucially, it MUST NOT match VT.
        if result.tool_name:
            self.assertNotEqual(result.tool_name, "url_scan_virustotal")

if __name__ == '__main__':
    unittest.main()
