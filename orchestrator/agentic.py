"""
Agentic mode: ti_lookup / ti_lookup_batch for unattended callers (TriageLoop).

Structured in, structured out. No natural-language routing, no embedding model, no clarifying
questions. Every call returns either

    {"ok": true, "source", "indicator_type", "indicator", "observed_facts", "cached", "athena_version"}
or
    {"ok": false, "reason": <REASON>, "source": <source or null>}

and writes exactly one audit entry (one per item for batches).
"""
import os
import re
import uuid
from typing import Any, Callable, Dict, Optional, Tuple

from orchestrator.cache import ResponseCache
from orchestrator.config import AthenaConfig, ConfigError, load_config
from orchestrator.indicators import INDICATOR_TYPES, IndicatorError, normalize_indicator
from orchestrator.registry import ToolRegistry
from orchestrator.version import ATHENA_VERSION
from tools import abuseipdb_tool, shodan_tool, threatfox_tool, virustotal_tool

# source name -> (registry tool name, implementation module)
SOURCES: Dict[str, Tuple[str, Any]] = {
    "shodan": ("ip_intel_shodan", shodan_tool),
    "virustotal": ("url_scan_virustotal", virustotal_tool),
    "abuseipdb": ("abuse_ip_db", abuseipdb_tool),
    "threatfox": ("threatfox_ioc", threatfox_tool),
}
TOOL_TO_SOURCE = {tool: source for source, (tool, _) in SOURCES.items()}

REASONS = (
    "invalid_request",             # arguments not an object, missing/extra/mistyped fields, bad caller
    "unknown_source",
    "source_disabled",             # disabled in registry/tools.json
    "invalid_indicator_type",
    "unsupported_indicator_type",  # valid type, but this source does not accept it
    "invalid_indicator",
    "non_routable_ip",             # private / loopback / link-local (same rule as ti_query)
    "approval_required",
    "missing_api_key",
    "upstream_rate_limited",
    "upstream_error",
    "config_error",
    "batch_too_large",
    "internal_error",
)

# Judgement keys ti_lookup must never emit, removed at any depth of observed_facts.
# Today only VirusTotal's derived "verdict" occurs; the rest guard against future tool changes.
# ti_query is unchanged (it still emits VirusTotal's verdict, as in v1.2).
STRIPPED_FACT_KEYS = frozenset({
    "verdict", "severity", "attribution", "remediation", "recommendation", "recommendations",
})


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items() if k not in STRIPPED_FACT_KEYS}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value

MAX_BATCH_ITEMS = 25
MAX_LOGGED_LENGTH = 512
_LOOKUP_FIELDS = ("source", "indicator_type", "indicator", "caller")
_CALLER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}")


# --- MCP schemas -------------------------------------------------------------------------------
_LOOKUP_INPUT = {
    "type": "object",
    "properties": {
        "source": {"type": "string", "enum": list(SOURCES)},
        "indicator_type": {"type": "string", "enum": list(INDICATOR_TYPES)},
        "indicator": {"type": "string", "description": "IPv4, domain, http(s) URL, or MD5/SHA1/SHA256 hash"},
        "caller": {"type": "string", "description": "Identifier of the calling system, e.g. 'triageloop'"},
    },
    "required": list(_LOOKUP_FIELDS),
    "additionalProperties": False,
}
TI_LOOKUP_INPUT_SCHEMA = _LOOKUP_INPUT
TI_LOOKUP_BATCH_INPUT_SCHEMA = {
    "type": "object",
    "properties": {"items": {"type": "array", "items": _LOOKUP_INPUT, "minItems": 1, "maxItems": MAX_BATCH_ITEMS}},
    "required": ["items"],
    "additionalProperties": False,
}

_FAILURE_OUTPUT = {
    "type": "object",
    "properties": {
        "ok": {"const": False},
        "reason": {"type": "string", "enum": list(REASONS)},
        "source": {"enum": list(SOURCES) + [None]},
    },
    "required": ["ok", "reason", "source"],
    "additionalProperties": False,
}
_SUCCESS_OUTPUT = {
    "type": "object",
    "properties": {
        "ok": {"const": True},
        "source": {"type": "string", "enum": list(SOURCES)},
        "indicator_type": {"type": "string", "enum": list(INDICATOR_TYPES)},
        "indicator": {"type": "string"},
        "observed_facts": {"type": "object"},
        "cached": {"type": "boolean"},
        "athena_version": {"type": "string"},
    },
    "required": ["ok", "source", "indicator_type", "indicator", "observed_facts", "cached", "athena_version"],
    "additionalProperties": False,
}
TI_LOOKUP_OUTPUT_SCHEMA = {"type": "object", "oneOf": [_SUCCESS_OUTPUT, _FAILURE_OUTPUT]}
TI_LOOKUP_BATCH_OUTPUT_SCHEMA = {
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "properties": {
                "ok": {"const": True},
                "results": {"type": "array", "items": TI_LOOKUP_OUTPUT_SCHEMA},
                "athena_version": {"type": "string"},
            },
            "required": ["ok", "results", "athena_version"],
            "additionalProperties": False,
        },
        _FAILURE_OUTPUT,
    ],
}


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_LOGGED_LENGTH:
        return value[:MAX_LOGGED_LENGTH] + "...[truncated]"
    return value if isinstance(value, (str, type(None))) else repr(value)[:MAX_LOGGED_LENGTH]


def _failure(reason: str, source: Optional[str]) -> Dict[str, Any]:
    assert reason in REASONS
    return {"ok": False, "reason": reason, "source": source if source in SOURCES else None}


def _upstream_reason(error: Any) -> str:
    return "upstream_rate_limited" if "429" in str(error) else "upstream_error"


class AgenticService:
    def __init__(
        self,
        registry: ToolRegistry,
        log_audit: Callable[[Dict[str, Any]], None],
        config_loader: Callable[[], AthenaConfig] = load_config,
    ):
        self.registry = registry
        self.log_audit = log_audit
        self.config_loader = config_loader

    # -- public API -----------------------------------------------------------------------------
    def lookup(self, arguments: Any, batch_id: Optional[str] = None, batch_index: Optional[int] = None) -> Dict[str, Any]:
        audit = {
            "routing": "agentic",
            "mcp_tool": "ti_lookup_batch" if batch_id else "ti_lookup",
            "caller": None, "source": None, "indicator_type": None, "indicator": None,
            "tool": None, "executed_tool": None, "cache_hit": False,
            "ok": False, "reason": None,
            "batch_id": batch_id, "batch_index": batch_index,
            "athena_version": ATHENA_VERSION,
        }
        try:
            response = self._lookup(arguments, audit)
        except Exception:
            response = _failure("internal_error", audit.get("source"))
        return self._finish(response, audit)

    def lookup_batch(self, arguments: Any) -> Dict[str, Any]:
        batch_id = uuid.uuid4().hex
        items = arguments.get("items") if isinstance(arguments, dict) else None
        reason = None
        if not isinstance(arguments, dict) or set(arguments) != {"items"} or not isinstance(items, list) or not items:
            reason = "invalid_request"
        elif len(items) > MAX_BATCH_ITEMS:
            reason = "batch_too_large"
        if reason:
            audit = {
                "routing": "agentic", "mcp_tool": "ti_lookup_batch", "caller": None, "source": None,
                "indicator_type": None, "indicator": None, "tool": None, "executed_tool": None,
                "cache_hit": False, "ok": False, "reason": reason, "batch_id": batch_id,
                "batch_index": None, "batch_size": len(items) if isinstance(items, list) else None,
                "athena_version": ATHENA_VERSION,
            }
            return self._finish(_failure(reason, None), audit)
        results = [self.lookup(item, batch_id=batch_id, batch_index=i) for i, item in enumerate(items)]
        return {"ok": True, "results": results, "athena_version": ATHENA_VERSION}

    # -- internals ------------------------------------------------------------------------------
    def _finish(self, response: Dict[str, Any], audit: Dict[str, Any]) -> Dict[str, Any]:
        audit["ok"] = response["ok"]
        audit["reason"] = response.get("reason")
        try:
            self.log_audit({"audit": audit, "response": response})
        except Exception:
            # An agentic call must never go unaudited: if the entry cannot be written, fail closed.
            return _failure("internal_error", response.get("source"))
        return response

    def _lookup(self, args: Any, audit: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(args, dict):
            return _failure("invalid_request", None)
        for field in _LOOKUP_FIELDS:
            audit[field] = _clip(args.get(field))
        source = args.get("source") if args.get("source") in SOURCES else None

        if set(args) != set(_LOOKUP_FIELDS) or not all(isinstance(args[f], str) for f in _LOOKUP_FIELDS):
            return _failure("invalid_request", source)
        caller = args["caller"]
        if not _CALLER_RE.fullmatch(caller):
            return _failure("invalid_request", source)
        if source is None:
            return _failure("unknown_source", None)

        tool_name, module = SOURCES[source]
        audit["tool"] = tool_name
        tool = self.registry.get_tool(tool_name)
        if tool is None or not tool.enabled:
            return _failure("source_disabled", source)

        indicator_type = args["indicator_type"]
        if indicator_type not in INDICATOR_TYPES:
            return _failure("invalid_indicator_type", source)
        if indicator_type not in tool.input_types:
            return _failure("unsupported_indicator_type", source)
        try:
            indicator = normalize_indicator(indicator_type, args["indicator"])
        except IndicatorError as e:
            return _failure(e.reason, source)
        audit["indicator"] = indicator

        try:
            config = self.config_loader()
        except ConfigError:
            return _failure("config_error", source)

        if not self._allowed(tool.risk_tier, caller, config):
            return _failure("approval_required", source)

        cache = ResponseCache(config.cache_dir, config.cache_ttl_seconds)
        data = cache.get(source, indicator)
        if data is not None:
            audit["cache_hit"] = True
        else:
            if tool.env_var_name and not os.environ.get(tool.env_var_name):
                return _failure("missing_api_key", source)
            audit["executed_tool"] = tool_name
            try:
                data = module.execute(indicator)
            except Exception:
                return _failure("upstream_error", source)
            if not isinstance(data, dict):
                return _failure("upstream_error", source)
            if "error" in data:
                return _failure(_upstream_reason(data["error"]), source)
            cache.put(source, indicator, data)

        return {
            "ok": True,
            "source": source,
            "indicator_type": indicator_type,
            "indicator": indicator,
            "observed_facts": _scrub(data),
            "cached": audit["cache_hit"],
            "athena_version": ATHENA_VERSION,
        }

    @staticmethod
    def _allowed(risk_tier: str, caller: str, config: AthenaConfig) -> bool:
        trusted = caller in config.trusted_callers
        if risk_tier == "low":
            return True
        if risk_tier == "medium":
            return trusted or not config.medium_risk_requires_approval
        return trusted  # high or unknown tiers: trusted callers only, regardless of the flag
