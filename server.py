#!/usr/bin/env python3
"""
Threat Intel MCP Server Entry Point
Responsibility: Expose the 'ti_query' tool via MCP stdio protocol.
"""
import asyncio
import os
import sys
import logging
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from pydantic import BaseModel, Field
import json
from typing import Dict, Any, Optional
from datetime import datetime

# Setup Logging (STDERR ONLY)
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger("ti-mcp-server")

# Audit Logging (File)
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
AUDIT_LOG_FILE = os.path.join(LOG_DIR, 'audit.jsonl')

def log_audit(entry: Dict[str, Any]):
    """Appends a JSON entry to the audit log."""
    with open(AUDIT_LOG_FILE, 'a') as f:
        entry['timestamp'] = datetime.now().isoformat()
        f.write(json.dumps(entry) + '\n')

# Orchestrator Imports
from orchestrator.entity import detect_entity
from orchestrator.router import SemanticRouter
from orchestrator.registry import ToolRegistry
from tools import shodan_tool, virustotal_tool

# Initialize Orchestrator Components
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load Env
load_dotenv(os.path.join(BASE_DIR, '.env'))

# Initialize Orchestrator Components
REGISTRY_PATH = os.path.join(BASE_DIR, 'registry', 'tools.json')

registry = ToolRegistry(REGISTRY_PATH)
router = SemanticRouter(registry)

# Initialize MCP Server
server = Server("ti-mcp-server")

# Schema Definition
class ThreatIntelResponse(BaseModel):
    ok: bool
    summary: str
    confidence: float
    data: Dict[str, Any]

import mcp.types as types

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="ti_query",
            description="Specialized Security & Threat Intel tool. Triggers on requests to 'scan', 'check', or 'analyze' IPs and URLs for malicious activity, malware, reputation, and exposure. Use this for security verdicts and technical infrastructure lookups.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The natural language query (e.g., 'Check IP 8.8.8.8')"
                    }
                },
                "required": ["query"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    
    if name != "ti_query":
        raise ValueError(f"Unknown tool: {name}")

    if not arguments or "query" not in arguments:
        raise ValueError("Missing 'query' argument")

    query = arguments["query"]
    
    # ---------------------------------------------------------
    # Core Logic (Moved from previous function)
    # ---------------------------------------------------------
    logger.info(f"Received query: {query}")
    
    # 1. Detect Entity
    entity = detect_entity(query)
    logger.info(f"Detected entity: {entity}")
    
    # 2. Route Query
    route = router.route_query(query, entity)
    logger.info(f"Routing result: {route}")
    
    # Audit Log
    audit = {
        "entity_detected": f"{entity.type.value}: {entity.value}",
        "routing_reason": route.reason,
        "selected_tool": route.tool_name,
        "confidence": route.confidence
    }

    # Create Reasoning String
    reasoning = f"Detection: {entity.type.value} was identified in query. Routing: {route.reason} with {route.confidence*100:.1f}% confidence."
    if route.tool_name:
        reasoning += f" Tool: {route.tool_name} was selected."
    
    # Final Response Construction
    final_response = None
    try:
        if not route.tool_name:
            final_response = ThreatIntelResponse(
                ok=False,
                summary="Routing failed",
                confidence=0.0,
                data={"error": { "type": "routing", "message": route.reason }}
            )
        else:
            # 3. Execute Tool (In a separate thread to avoid blocking the MCP loop)
            tool_data = {}
            if route.tool_name == "ip_intel_shodan":
                tool_data = await asyncio.to_thread(shodan_tool.execute, entity.value)
            elif route.tool_name == "url_scan_virustotal":
                tool_data = await asyncio.to_thread(virustotal_tool.execute, entity.value)
            else:
                 final_response = ThreatIntelResponse(
                    ok=False,
                    summary="Execution failed (Tool Not Found)",
                    confidence=0.0,
                    data={"error": { "type": "execution", "message": f"Tool implementation not found for {route.tool_name}" }}
                )

            if not final_response:
                # Check for tool-level errors
                if "error" in tool_data:
                    final_response = ThreatIntelResponse(
                        ok=False,
                        summary=f"Execution failed in {route.tool_name}",
                        confidence=route.confidence,
                        data=tool_data
                    )
                else:
                    # 4. Return Success
                    final_response = ThreatIntelResponse(
                        ok=True,
                        summary=f"Successfully executed {route.tool_name}",
                        confidence=route.confidence,
                        data=tool_data
                    )

    except Exception as e:
        final_response = ThreatIntelResponse(
            ok=False,
            summary=f"Exception during execution",
            confidence=0.0,
            data={"error": { "type": "exception", "message": str(e) }}
        )

    # Prepare final dict (for CLI)
    response_dict = final_response.model_dump()

    # Record to Audit Log (Full details kept here)
    audit_entry = {
        "query": query, 
        "response": response_dict,
        "reasoning": reasoning,
        "audit": audit
    }
    log_audit(audit_entry)

    # Serialize to JSON TextContent
    return [
        types.TextContent(
            type="text",
            text=json.dumps(response_dict, indent=2)
        )
    ]

async def main():
    # Run the server using stdin/stdout streams
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
