"""
Router Module
Responsibility: Semantically route queries to the best tool using 3-layer logic.
Layer A: Entity Type Filter
Layer B: Semantic Intent Matching (SentenceTransformers)
Layer C: Policy Enforcement
"""
import os
import numpy as np
import logging
from sentence_transformers import SentenceTransformer
from typing import Optional, Dict, Any, NamedTuple
from .entity import EntityType, DetectedEntity
from .registry import ToolRegistry, ToolDefinition

# Suppress Transformers/Tokenizers noise
os.environ["TOKENIZERS_PARALLELISM"] = "false"
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)

# Config
MODEL_NAME = 'all-MiniLM-L6-v2'
DEFAULT_THRESHOLD = 0.30

class RoutingResult(NamedTuple):
    tool_name: Optional[str]
    confidence: float
    reason: str

class SemanticRouter:
    def __init__(self, registry: ToolRegistry):
        self.registry = registry
        self._model = None
        self.threshold = float(os.getenv('ROUTER_THRESHOLD', DEFAULT_THRESHOLD))
        self._cached_embeddings = {}  # {tool_name: ndarray}

    @property
    def model(self):
        if self._model is None:
            logging.info("🧠 Loading Router Embeddings Model (Lazy)...")
            self._model = SentenceTransformer(MODEL_NAME)
        return self._model

    def _get_tool_embeddings(self, tool: ToolDefinition) -> np.ndarray:
        """Retrieves or calculates embeddings for a tool's intents."""
        if tool.name not in self._cached_embeddings:
            logging.info(f"✨ Caching embeddings for tool: {tool.name}")
            self._cached_embeddings[tool.name] = self.model.encode(tool.intents)
        return self._cached_embeddings[tool.name]

    def route_query(self, query: str, entity: DetectedEntity) -> RoutingResult:
        """
        Routes a query to a tool based on Entity, Intent, and Policy.
        """
        # --- LAYER A: Entity Filter ---
        candidates = [
            t for t in self.registry.get_enabled_tools()
            if t.input_type == entity.type.value
        ]
        
        if not candidates:
            return RoutingResult(None, 0.0, f"No enabled tools for entity type: {entity.type.value}")

        # --- LAYER B: Semantic Matching ---
        # 1. Strip entity from query to improve signal
        cleaned_query = query.replace(entity.value, "").strip()
        if not cleaned_query: # Fallback if query ONLY contained the entity
            cleaned_query = query

        # 2. Embed query
        query_embedding = self.model.encode([cleaned_query])
        
        # 3. Score candidates
        best_tool = None
        best_score = -1.0
        
        for tool in candidates:
            # Use cached embeddings
            intent_embeddings = self._get_tool_embeddings(tool)
            
            # shape: (1, 384) . (N, 384).T = (1, N)
            # Find max similarity across all intents for this tool
            similarities = np.dot(query_embedding, intent_embeddings.T)[0]
            max_sim = np.max(similarities)
            
            if max_sim > best_score:
                best_score = max_sim
                best_tool = tool

        # 3. Check Threshold
        normalized_score = float(best_score)
        if normalized_score < self.threshold:
             return RoutingResult(None, normalized_score, f"Intent confidence ({normalized_score:.2f}) below threshold ({self.threshold})")

        # --- LAYER C: Policy Enforcement ---
        if not best_tool.enabled:
             return RoutingResult(None, normalized_score, f"Tool '{best_tool.name}' is disabled by policy.")

        return RoutingResult(best_tool.name, normalized_score, "Semantic match passed threshold")
