"""
mcp_server.py — Threat Intelligence Model Context Protocol (MCP) Server

Initializes a FastMCP server named "Threat-Intel-MCP" exposing threat searching,
container diagnostic tools, and threat severity analysis for LLM agents.
"""

import re
import json
import logging
import subprocess
import urllib.request
from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator
from elasticsearch import Elasticsearch
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    from mcp.server.mcpserver import MCPServer as FastMCP
from config import ES_HOST, ES_INDEX

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Threat-Intel-MCP")

# Initialize FastMCP Server
mcp = FastMCP("Threat-Intel-MCP")


# ============================================================================
# Guardrails & Input Validation Layer
# ============================================================================

class SearchLogsParams(BaseModel):
    query: str = Field(..., max_length=250, description="Search term or query string")
    index_pattern: str = Field(default="threat-intel-iocs", max_length=100, description="Target index or pattern")
    timeframe_minutes: int = Field(default=60, ge=1, le=525600, description="Lookback window in minutes")

    @field_validator("query")
    @classmethod
    def sanitize_query(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Query string cannot be empty.")
        # Guardrail: Prevent Lucene script injection and dangerous payload keywords
        forbidden_patterns = [r"script", r"doc\[", r"_source", r"ctx\._source", r"DELETE", r"DROP"]
        for pattern in forbidden_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError(f"Query contains forbidden pattern/keyword: {pattern}")
        # Strip excessive leading wildcards to prevent query performance degradation
        v = re.sub(r"^\*+", "", v)
        return v

    @field_validator("index_pattern")
    @classmethod
    def sanitize_index_pattern(cls, v: str) -> str:
        v = v.strip().lower()
        # Disallow system indices starting with '.' or path traversal characters
        if v.startswith(".") or "/" in v or "\\" in v:
            raise ValueError("Access to system indices or invalid index patterns is forbidden.")
        # Only allow alphanumeric, hyphens, underscores, and trailing asterisk
        if not re.match(r"^[a-z0-9_\-\*]+$", v):
            raise ValueError("Invalid characters in index_pattern name.")
        return v


class ThreatAnalysisParams(BaseModel):
    failed_logins: int = Field(..., ge=0, description="Number of failed login attempts")
    unauthorized_attempts: int = Field(..., ge=0, description="Number of unauthorized HTTP 401/403 attempts")


# ============================================================================
# MCP Tools
# ============================================================================

@mcp.tool()
def search_logs(
    query: str,
    index_pattern: str = "threat-intel-iocs",
    timeframe_minutes: int = 60
) -> str:
    """
    Query matching threat hits/log entries from Elasticsearch within a timeframe.

    Args:
        query: Free-text search term or IOC value (e.g. 'Emotet', 'botnet_c2', '162.243.103.246').
        index_pattern: Elasticsearch index pattern (default: 'threat-intel-iocs').
        timeframe_minutes: Lookback duration in minutes (default: 60).

    Returns:
        JSON string containing matching threat logs, total hits, and status.
    """
    try:
        # Validate inputs via Pydantic guardrails
        params = SearchLogsParams(
            query=query,
            index_pattern=index_pattern,
            timeframe_minutes=timeframe_minutes
        )

        es = Elasticsearch(ES_HOST, request_timeout=15)
        if not es.ping():
            return json.dumps({
                "status": "error",
                "message": f"Elasticsearch unreachable at {ES_HOST}. Verify Docker container status.",
                "total_hits": 0,
                "results": []
            }, indent=2)

        # Build secure search request
        es_query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": params.query,
                                "default_field": "*",
                                "analyze_wildcard": False
                            }
                        }
                    ],
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{params.timeframe_minutes}m"
                                }
                            }
                        }
                    ]
                }
            },
            "size": 50,
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

        response = es.search(index=params.index_pattern, body=es_query)
        hits = response.get("hits", {}).get("hits", [])
        total_value = response.get("hits", {}).get("total", {}).get("value", 0)

        cleaned_hits = []
        for hit in hits:
            source = hit.get("_source", {})
            cleaned_hits.append({
                "id": hit.get("_id"),
                "ioc_value": source.get("ioc_value"),
                "ioc_type": source.get("ioc_type"),
                "source": source.get("source"),
                "threat_type": source.get("threat_type"),
                "confidence": source.get("confidence"),
                "country": source.get("country"),
                "vt_score": source.get("vt_score"),
                "timestamp": source.get("@timestamp")
            })

        return json.dumps({
            "status": "success",
            "query": params.query,
            "index": params.index_pattern,
            "timeframe_minutes": params.timeframe_minutes,
            "total_hits": total_value,
            "returned_count": len(cleaned_hits),
            "results": cleaned_hits
        }, indent=2)

    except Exception as e:
        logger.error("search_logs error: %s", e)
        return json.dumps({
            "status": "error",
            "message": str(e),
            "total_hits": 0,
            "results": []
        }, indent=2)


@mcp.tool()
def get_container_status() -> str:
    """
    Check operational status of Docker containers (Elasticsearch, Logstash, Kibana).

    Returns:
        JSON string detailing container states, health checks, and service endpoints.
    """
    services_status = {}

    # Check Elasticsearch API endpoint
    try:
        req = urllib.request.urlopen(f"{ES_HOST}/_cluster/health", timeout=5)
        if req.status == 200:
            health_data = json.loads(req.read().decode("utf-8"))
            services_status["elasticsearch_api"] = {
                "status": "healthy",
                "cluster_name": health_data.get("cluster_name"),
                "cluster_status": health_data.get("status"),
                "number_of_nodes": health_data.get("number_of_nodes")
            }
        else:
            services_status["elasticsearch_api"] = {"status": "unhealthy", "code": req.status}
    except Exception as e:
        services_status["elasticsearch_api"] = {"status": "unreachable", "error": str(e)}

    # Check Kibana API endpoint
    try:
        req = urllib.request.urlopen("http://localhost:5601/api/status", timeout=5)
        if req.status == 200:
            services_status["kibana_api"] = {"status": "healthy", "url": "http://localhost:5601"}
        else:
            services_status["kibana_api"] = {"status": "unhealthy", "code": req.status}
    except Exception as e:
        services_status["kibana_api"] = {"status": "unreachable", "error": str(e)}

    # Execute docker ps check
    try:
        res = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}|{{.Status}}|{{.State}}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        containers = []
        if res.returncode == 0 and res.stdout:
            for line in res.stdout.strip().split("\n"):
                if "|" in line:
                    parts = line.split("|")
                    containers.append({
                        "name": parts[0],
                        "status": parts[1],
                        "state": parts[2]
                    })
        services_status["docker_containers"] = containers
    except Exception as e:
        services_status["docker_containers"] = f"Unable to query Docker daemon: {str(e)}"

    return json.dumps({
        "status": "success",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": services_status
    }, indent=2)


@mcp.tool()
def analyze_threat_level(failed_logins: int, unauthorized_attempts: int) -> str:
    """
    Analyze security event metrics and calculate threat severity classification.

    Args:
        failed_logins: Count of failed authentication attempts.
        unauthorized_attempts: Count of unauthorized resource access / HTTP 401/403 events.

    Returns:
        JSON string with severity classification (LOW, MEDIUM, HIGH, CRITICAL) and action steps.
    """
    try:
        params = ThreatAnalysisParams(
            failed_logins=failed_logins,
            unauthorized_attempts=unauthorized_attempts
        )

        # Risk scoring calculation
        risk_score = (params.failed_logins * 2) + (params.unauthorized_attempts * 5)

        if risk_score >= 80 or params.unauthorized_attempts >= 15 or params.failed_logins >= 40:
            severity = "CRITICAL"
            description = "Active brute-force attack or unauthorized intrusion attempt in progress."
            actions = [
                "Immediately block source IP addresses at firewall level.",
                "Revoke compromise-suspected session tokens and trigger emergency password resets.",
                "Escalate incident to Tier-3 SOC analyst and initiate Incident Response (IR) playbook.",
                "Isolate affected server resources from non-essential network paths."
            ]
        elif risk_score >= 35 or params.unauthorized_attempts >= 6 or params.failed_logins >= 15:
            severity = "HIGH"
            description = "Elevated volume of suspicious access attempts detected."
            actions = [
                "Enforce mandatory Multi-Factor Authentication (MFA) for target accounts.",
                "Place requesting IP addresses on temporary rate-limiting / CAPTCHA list.",
                "Review Elasticsearch audit logs for correlated IOCs.",
                "Notify SOC tier-2 team for monitoring."
            ]
        elif risk_score >= 10 or params.unauthorized_attempts >= 2 or params.failed_logins >= 5:
            severity = "MEDIUM"
            description = "Moderate authentication anomalies observed above baseline."
            actions = [
                "Monitor source IPs for continued retry activity.",
                "Cross-reference user accounts with known compromised password databases.",
                "Ensure rate-limiting policies are active on login endpoints."
            ]
        else:
            severity = "LOW"
            description = "Normal operational variance or sporadic user login typos."
            actions = [
                "No immediate intervention required.",
                "Log event telemetry for standard baseline analysis."
            ]

        return json.dumps({
            "status": "success",
            "severity": severity,
            "risk_score": risk_score,
            "metrics": {
                "failed_logins": params.failed_logins,
                "unauthorized_attempts": params.unauthorized_attempts
            },
            "assessment": description,
            "recommended_actions": actions
        }, indent=2)

    except Exception as e:
        logger.error("analyze_threat_level error: %s", e)
        return json.dumps({
            "status": "error",
            "message": str(e)
        }, indent=2)


if __name__ == "__main__":
    mcp.run()
