"""
Tool Registry Module
Responsibility: Load and validate tool definitions from JSON.
"""
import json
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class ToolDefinition:
    name: str
    input_types: List[str]  # Changed from single input_type
    intents: List[str]
    risk_tier: str
    requires_approval: bool
    enabled: bool
    requires_api_key: bool
    env_var_name: Optional[str] = None

class ToolRegistry:
    def __init__(self, registry_path: str):
        self.registry_path = registry_path
        self.tools: List[ToolDefinition] = []
        self._load_registry()

    def _load_registry(self):
        if not os.path.exists(self.registry_path):
            raise FileNotFoundError(f"Registry not found at: {self.registry_path}")

        try:
            with open(self.registry_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            for tool_data in data.get('tools', []):
                # Handle legacy single input_type or new list
                input_types = tool_data.get('input_types')
                if not input_types:
                    input_types = [tool_data.get('input_type', 'unknown')]

                self.tools.append(ToolDefinition(
                    name=tool_data['name'],
                    input_types=input_types,
                    intents=tool_data['intents'],
                    risk_tier=tool_data.get('risk_tier', 'low'),
                    requires_approval=tool_data.get('requires_user_approval', False),
                    enabled=tool_data.get('enabled', True),
                    requires_api_key=tool_data.get('requires_api_key', False),
                    env_var_name=tool_data.get('env_var_name')
                ))
        except Exception as e:
            raise RuntimeError(f"Failed to load tool registry: {e}")

    def get_enabled_tools(self) -> List[ToolDefinition]:
        return [t for t in self.tools if t.enabled]

    def get_tool(self, name: str) -> ToolDefinition:
        for tool in self.tools:
            if tool.name == name:
                return tool
        return None
