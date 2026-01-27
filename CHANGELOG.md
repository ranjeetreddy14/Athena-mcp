# Version History

## v1.2 - Analyst-Augmented Output
*Released: February 2026*

**What's New:**
- **Three-Lane Output Schema:** Athena now separates `observed_facts` (tool-derived, authoritative), `analyst_interpretation` (LLM-rendered), and `recommended_next_steps` (LLM-rendered).
- **Senior CTI Persona Prompt:** Use the `senior_cti_analyst` MCP Prompt at session startup to inject the Senior CTI Analyst persona and guarantee authoritative behavior.
- **Audit Hashing:** Every response now includes a `persona_hash` (SHA256) in the audit block, proving which persona version governed the session.
- **Enhanced LLM Guardrails:** The persona explicitly prohibits the LLM from claiming execution authority, issuing autonomous verdicts, or fabricating technical details.
- **Verdict Leakage Hardening:** Updated `ti_query` tool description to strictly forbid authoritative verdicts.
- **Output Governance:** Added immutable `analysis_constraints` to the response schema.

**Schema Changes (Breaking):**
- `data` field renamed to `observed_facts` to emphasize authoritative nature
- Added `analyst_interpretation` field (always `null` from server)
- Added `recommended_next_steps` field (always `null` from server)

---

## v1.1 - Expanded Threat Intelligence
*Released: January 2026*

**What's New:**
- **New Threat Intelligence Sources:** Added full integration with **AbuseIPDB** for IP reputation and **ThreatFox** for IOC database lookups.
- **Hash Support:** You can now query MD5, SHA1, and SHA256 hashes directly.
- **Smart Workflows:** Added interactive confirmation flows for sensitive or credit-consuming tools.
- **Enhanced Detection:** Improved entity detection engine to automatically distinguish between IPs, URLs, Domains, and Hashes with higher accuracy.
- **Audit Logging:** Implemented structured audit logging for all queries and tool executions.

## v1.0 - Initial Release
*Released: December 2025*

**What's New:**
- **Athena Core:** Initial release of the Threat Intelligence MCP Server.
- **Shodan Integration:** Native support for IP geolocation and open port scanning.
- **VirusTotal Integration:** deep scanning capabilities for URLs and Domains.
- **Semantic Routing:** AI-powered intent matching to automatically select the right tool for your query.
- **MCP Compatibility:** Full support for the Model Context Protocol (stdio transport).
