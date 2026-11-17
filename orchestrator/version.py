"""
Single in-code version constant.

Kept equal to pyproject.toml [project].version and capabilities.json "athena_version"
by tests/test_capabilities.py. TriageLoop records this value per case.
"""
ATHENA_VERSION = "1.3.0"

# Version of the agentic (ti_lookup / ti_lookup_batch) request/response contract.
# Bump only on a breaking change to that contract.
AGENTIC_CONTRACT_VERSION = "1"
