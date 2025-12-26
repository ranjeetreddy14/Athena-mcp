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
from typing import Dict, Any, Optional, List
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
from tools import shodan_tool, virustotal_tool, abuseipdb_tool, threatfox_tool

# Initialize Orchestrator Components
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load Env
load_dotenv(os.path.join(BASE_DIR, '.env'))

# Initialize Orchestrator Components
REGISTRY_PATH = os.path.join(BASE_DIR, 'registry', 'tools.json')

registry = ToolRegistry(REGISTRY_PATH)
router = SemanticRouter(registry)

# Initialize MCP Server
server = Server("athena")

# Schema Definition
class ThreatIntelResponse(BaseModel):
    ok: bool
    summary: str
    confidence: float
    data: Optional[Dict[str, Any]] = None
    audit: Optional[Dict[str, Any]] = None
    suggestions: Optional[List[str]] = None

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
        if entity.type.value == "hash":
            # --- SPECIAL WORKFLOW: Hashes ---
            # Prioritize ThreatFox unless user explicitly asks for VirusTotal or gives approval
            vt_keywords = ["virustotal", "vt", "yes", "approve", "confirm", "proceed", "scan vt"]
            wants_vt = any(word in query.lower() for word in vt_keywords)

            if wants_vt:
                logger.info("Executing VirusTotal (User Approved/Requested for Hash)")
                tool_data = await asyncio.to_thread(virustotal_tool.execute, entity.value)
                final_response = ThreatIntelResponse(
                    ok="error" not in tool_data,
                    summary=f"Successfully executed VirusTotal scan for hash" if "error" not in tool_data else tool_data.get("error"),
                    confidence=1.0, # Direct override
                    data=tool_data if "error" not in tool_data else None,
                    audit={"tool": "url_scan_virustotal", "entity": "hash", "input": entity.value}
                )
            else:
                logger.info("Executing ThreatFox (Default for Hash)")
                tool_data = await asyncio.to_thread(threatfox_tool.execute, entity.value)
                
                if tool_data.get("status") == "no_result":
                    final_response = ThreatIntelResponse(
                        ok=False,
                        summary="No results found in ThreatFox.",
                        confidence=1.0,
                        suggestions=[
                            f"Would you like to perform a deeper scan on VirusTotal for this hash? (Reply 'Yes, check VirusTotal')"
                        ]
                    )
                else:
                    final_response = ThreatIntelResponse(
                        ok="error" not in tool_data,
                        summary=f"Successfully executed ThreatFox" if "error" not in tool_data else tool_data.get("error"),
                        confidence=1.0,
                        data=tool_data if "error" not in tool_data else None,
                        audit={"tool": "threatfox_ioc", "entity": "hash", "input": entity.value}
                    )

        elif not route.tool_name:
            final_response = ThreatIntelResponse(
                ok=False,
                summary="Entity detected but intent was unclear." if entity.type != EntityType.UNKNOWN else "No technical identifier detected.",
                confidence=route.confidence,
                suggestions=route.suggestions if route.suggestions else ["Try including an IP, URL, domain, or hash in your query."]
            )
        else:
            # --- STANDARD WORKFLOW: IPs, URLs, Domains ---
            selected_tool_def = next((t for t in registry.tools if t.name == route.tool_name), None)
            needs_approval = selected_tool_def and selected_tool_def.requires_approval
            confirmation_keywords = ["yes", "approve", "confirm", "proceed", "okay", "ok", "go ahead"]
            is_confirmed = any(word in query.lower() for word in confirmation_keywords)

            if needs_approval and not is_confirmed:
                final_response = ThreatIntelResponse(
                    ok=False,
                    summary=f"Permission Required: Tool '{route.tool_name}' requires explicit user approval.",
                    confidence=route.confidence,
                    suggestions=[
                        f"Reply with 'yes' or 'proceed' to execute {route.tool_name} for this query."
                    ]
                )
            else:
                # Execute Tool
                tool_data = {}
                try:
                    if route.tool_name == "ip_intel_shodan":
                        tool_data = await asyncio.to_thread(shodan_tool.execute, entity.value)
                    elif route.tool_name == "url_scan_virustotal":
                        tool_data = await asyncio.to_thread(virustotal_tool.execute, entity.value)
                    elif route.tool_name == "abuse_ip_db":
                        tool_data = await asyncio.to_thread(abuseipdb_tool.execute, entity.value)
                    elif route.tool_name == "threatfox_ioc":
                        tool_data = await asyncio.to_thread(threatfox_tool.execute, entity.value)
                    else:
                        tool_data = {"error": f"Tool implementation '{route.tool_name}' not found."}
                except Exception as e:
                    tool_data = {"error": f"Tool execution failed: {str(e)}"}

                final_response = ThreatIntelResponse(
                    ok="error" not in tool_data,
                    summary=f"Successfully executed {route.tool_name}" if "error" not in tool_data else tool_data.get("error"),
                    confidence=route.confidence,
                    data=tool_data if "error" not in tool_data else None,
                    audit={
                        "tool": route.tool_name,
                        "entity": entity.type.value,
                        "input": entity.value
                    }
                )

    except Exception as e:
        error_msg = f"Athena Server Error: {str(e)}"
        logger.error(error_msg)
        final_response = ThreatIntelResponse(
            ok=False,
            summary=error_msg,
            confidence=0.0
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
