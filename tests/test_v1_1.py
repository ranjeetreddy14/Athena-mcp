import unittest
from orchestrator.entity import detect_entity, EntityType
from orchestrator.registry import ToolRegistry
from orchestrator.router import SemanticRouter
import os

class TestAthenaV11(unittest.TestCase):
    def test_hash_detection(self):
        """Test detection of MD5, SHA1, and SHA256 hashes."""
        md5 = "5d41402abc4b2a76b9719d911017c592"
        sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        
        for h in [md5, sha1, sha256]:
            entity = detect_entity(h)
            self.assertEqual(entity.type, EntityType.HASH)
            self.assertEqual(entity.value, h)

    def test_multi_input_routing(self):
        """Test that tools are filtered correctly by multiple input types."""
        # Use a real tools.json for testing
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        registry_path = os.path.join(base_dir, 'registry', 'tools.json')
        registry = ToolRegistry(registry_path)
        router = SemanticRouter(registry)
        
        # ThreatFox should handle IP, Domain, URL, and Hash
        for query, e_type in [
            ("check ip 1.1.1.1 on threatfox", EntityType.IP),
            ("has malware been seen on example.com", EntityType.DOMAIN),
            ("check link http://malicious.cat on threatfox", EntityType.URL),
            ("search threatfox for hash 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", EntityType.HASH)
        ]:
            entity = detect_entity(query)
            self.assertEqual(entity.type, e_type)
            route = router.route_query(query, entity)
            self.assertEqual(route.tool_name, "threatfox_ioc")

    def test_ambiguous_query_suggestions(self):
        """Test that ambiguous queries return helpful suggestions."""
        registry_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'registry', 'tools.json')
        registry = ToolRegistry(registry_path)
        router = SemanticRouter(registry)
        
        query = "tell me about 8.8.8.8"
        entity = detect_entity(query)
        route = router.route_query(query, entity)
        
        self.assertIsNone(route.tool_name)
        self.assertTrue(len(route.suggestions) > 0)
        self.assertIn("Ask about geolocation or infrastructure (Shodan)", route.suggestions)

if __name__ == '__main__':
    unittest.main()
