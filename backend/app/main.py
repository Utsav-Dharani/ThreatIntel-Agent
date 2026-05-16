import re
from typing import Any, Dict, List, Literal, Optional

import oracledb
from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.agents.threatintel_agent import run_threatintel_agent
from app.database import get_connection
from app.services.analysis_repository import (
    create_analysis_row,
    insert_agent_step,
    mark_analysis_failed,
    save_threatintel_result,
)
from app.services.content_ingestion import (
    extract_text_from_pdf_bytes,
    extract_text_from_url,
)


app = FastAPI(
    title="ThreatIntel Agent API",
    description="Backend API for ThreatIntel Agent",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CreateAnalysisRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    source_type: Literal["TEXT", "URL", "PDF"]
    raw_content: str = Field(..., min_length=10)
    source_url: Optional[str] = None
    original_file_name: Optional[str] = None
    user_id: Optional[int] = 1
    client_id: Optional[str] = None


class TextAnalysisRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    raw_content: str = Field(..., min_length=20)
    user_id: Optional[int] = 1
    client_id: Optional[str] = None


class UrlAnalysisRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    url: str = Field(..., min_length=10)
    user_id: Optional[int] = 1
    client_id: Optional[str] = None


def _lob_to_text(value):
    if isinstance(value, oracledb.LOB):
        return value.read()
    return value


def _row_to_dict(cursor, row):
    columns = [column[0].lower() for column in cursor.description]
    result = {}

    for index, value in enumerate(row):
        result[columns[index]] = _lob_to_text(value)

    return result


def _get_returned_id(return_var) -> int:
    value = return_var.getvalue()

    if isinstance(value, list):
        return int(value[0])

    return int(value)


def _as_list(value):
    if isinstance(value, list):
        return value
    return []


def get_or_create_guest_user(client_id: str) -> int:
    safe_client_id = re.sub(r"[^A-Za-z0-9_-]", "", client_id or "")[:80]

    if len(safe_client_id) < 8:
        raise ValueError("Invalid browser session id.")

    guest_email = f"guest_{safe_client_id}@threatintel.local"

    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT USER_ID
            FROM USERS
            WHERE EMAIL = :email
            """,
            {"email": guest_email},
        )

        row = cursor.fetchone()

        if row:
            return int(row[0])

        user_id_var = cursor.var(oracledb.NUMBER)

        cursor.execute(
            """
            INSERT INTO USERS (
                FULL_NAME,
                EMAIL,
                PASSWORD_HASH,
                ROLE,
                CREATED_AT,
                UPDATED_AT
            )
            VALUES (
                :full_name,
                :email,
                :password_hash,
                'USER',
                SYSTIMESTAMP,
                SYSTIMESTAMP
            )
            RETURNING USER_ID INTO :user_id
            """,
            {
                "full_name": "Guest Analyst",
                "email": guest_email,
                "password_hash": "GUEST_BROWSER_SESSION",
                "user_id": user_id_var,
            },
        )

        connection.commit()
        return _get_returned_id(user_id_var)

    except oracledb.IntegrityError:
        if connection:
            connection.rollback()

        cursor.execute(
            """
            SELECT USER_ID
            FROM USERS
            WHERE EMAIL = :email
            """,
            {"email": guest_email},
        )

        row = cursor.fetchone()

        if not row:
            raise

        return int(row[0])

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def resolve_user_id(
    user_id: Optional[int] = None,
    client_id: Optional[str] = None,
) -> int:
    if client_id:
        return get_or_create_guest_user(client_id)

    return user_id or 1


def list_user_analyses(user_id: int) -> List[Dict[str, Any]]:
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                ANALYSIS_ID,
                TITLE,
                SOURCE_TYPE,
                SOURCE_URL,
                STATUS,
                RISK_SCORE,
                RISK_LEVEL,
                CREATED_AT,
                UPDATED_AT
            FROM ANALYSES
            WHERE USER_ID = :user_id
            ORDER BY CREATED_AT DESC
            """,
            {"user_id": user_id},
        )

        return [_row_to_dict(cursor, row) for row in cursor.fetchall()]

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def fetch_related_rows(table_name: str, analysis_id: int) -> List[Dict[str, Any]]:
    allowed_tables = {
        "AGENT_STEPS",
        "THREAT_ENTITIES",
        "INDICATORS",
        "CVES",
        "MITRE_TECHNIQUES",
        "ATTACK_CHAIN_STEPS",
        "RECOMMENDATIONS",
        "EVIDENCE_FINDINGS",
    }

    if table_name not in allowed_tables:
        raise ValueError("Invalid related table.")

    order_by = "CREATED_AT"

    if table_name in {"AGENT_STEPS", "ATTACK_CHAIN_STEPS"}:
        order_by = "STEP_ORDER"

    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            f"""
            SELECT *
            FROM {table_name}
            WHERE ANALYSIS_ID = :analysis_id
            ORDER BY {order_by}
            """,
            {"analysis_id": analysis_id},
        )

        return [_row_to_dict(cursor, row) for row in cursor.fetchall()]

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def get_user_analysis_detail(
    analysis_id: int,
    user_id: int,
) -> Optional[Dict[str, Any]]:
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                ANALYSIS_ID,
                USER_ID,
                TITLE,
                SOURCE_TYPE,
                SOURCE_URL,
                ORIGINAL_FILE_NAME,
                RAW_CONTENT,
                CLEANED_CONTENT,
                STATUS,
                RISK_SCORE,
                RISK_LEVEL,
                CONFIDENCE_SCORE,
                EXECUTIVE_SUMMARY,
                FINAL_REPORT,
                ERROR_MESSAGE,
                CREATED_AT,
                UPDATED_AT
            FROM ANALYSES
            WHERE ANALYSIS_ID = :analysis_id
            AND USER_ID = :user_id
            """,
            {
                "analysis_id": analysis_id,
                "user_id": user_id,
            },
        )

        row = cursor.fetchone()

        if not row:
            return None

        analysis = _row_to_dict(cursor, row)

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    analysis["agent_steps"] = fetch_related_rows("AGENT_STEPS", analysis_id)
    analysis["threat_entities"] = fetch_related_rows("THREAT_ENTITIES", analysis_id)
    analysis["indicators"] = fetch_related_rows("INDICATORS", analysis_id)
    analysis["cves"] = fetch_related_rows("CVES", analysis_id)
    analysis["mitre_techniques"] = fetch_related_rows("MITRE_TECHNIQUES", analysis_id)
    analysis["attack_chain_steps"] = fetch_related_rows("ATTACK_CHAIN_STEPS", analysis_id)
    analysis["recommendations"] = fetch_related_rows("RECOMMENDATIONS", analysis_id)
    analysis["evidence_findings"] = fetch_related_rows("EVIDENCE_FINDINGS", analysis_id)

    return analysis


def _safe_number(value, default=0):
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _safe_int(value, default=1):
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _normalize_choice(value, allowed, default):
    if not value:
        return default

    normalized = str(value).strip().upper()

    if normalized in allowed:
        return normalized

    return default


def fetch_mitre_refs() -> Dict[str, Dict[str, Any]]:
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                TECHNIQUE_ID,
                TECHNIQUE_NAME,
                TACTIC,
                DESCRIPTION
            FROM MITRE_TECHNIQUE_REF
            """
        )

        refs = {}

        for row in cursor.fetchall():
            refs[row[0]] = {
                "technique_id": row[0],
                "technique_name": row[1],
                "tactic": row[2],
                "description": _lob_to_text(row[3]),
            }

        return refs

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def enrich_with_mitre_reference(result: Dict[str, Any]) -> Dict[str, Any]:
    refs = fetch_mitre_refs()

    for technique in _as_list(result.get("mitre_techniques")):
        if not isinstance(technique, dict):
            continue

        technique_id = str(technique.get("technique_id", "")).strip()

        if not technique_id:
            continue

        base_id = technique_id.split(".")[0]
        ref = refs.get(technique_id) or refs.get(base_id)

        if not ref:
            continue

        technique["technique_name"] = technique.get("technique_name") or ref["technique_name"]
        technique["tactic"] = technique.get("tactic") or ref["tactic"]
        technique["description"] = technique.get("description") or ref["description"]

    return result


def fetch_recommendation_rules() -> List[Dict[str, Any]]:
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                MATCH_TYPE,
                MATCH_VALUE,
                CATEGORY,
                PRIORITY,
                RECOMMENDATION_TEXT
            FROM RECOMMENDATION_RULES
            ORDER BY RULE_ID
            """
        )

        rules = []

        for row in cursor.fetchall():
            rules.append(
                {
                    "match_type": row[0],
                    "match_value": row[1],
                    "category": row[2],
                    "priority": row[3],
                    "recommendation_text": _lob_to_text(row[4]),
                }
            )

        return rules

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def append_rule_based_recommendations(result: Dict[str, Any]) -> Dict[str, Any]:
    result.setdefault("recommendations", [])

    if not isinstance(result["recommendations"], list):
        result["recommendations"] = []

    existing_texts = {
        str(item.get("recommendation_text", "")).strip().lower()
        for item in result["recommendations"]
        if isinstance(item, dict)
    }

    mitre_ids = {
        str(item.get("technique_id", "")).upper()
        for item in _as_list(result.get("mitre_techniques"))
        if isinstance(item, dict)
    }

    mitre_base_ids = {
        technique_id.split(".")[0]
        for technique_id in mitre_ids
        if technique_id
    }

    indicator_types = {
        str(item.get("indicator_type", "")).upper()
        for item in _as_list(result.get("indicators"))
        if isinstance(item, dict)
    }

    cve_severities = {
        str(item.get("severity", "")).upper()
        for item in _as_list(result.get("cves"))
        if isinstance(item, dict)
    }

    risk_level = str(result.get("risk_level", "")).upper()

    for rule in fetch_recommendation_rules():
        match_type = str(rule["match_type"]).upper()
        match_value = str(rule["match_value"]).upper()

        is_match = False

        if match_type == "MITRE":
            is_match = match_value in mitre_ids or match_value in mitre_base_ids

        if match_type == "IOC":
            is_match = match_value in indicator_types

        if match_type == "CVE":
            is_match = match_value in cve_severities

        if match_type == "RISK":
            is_match = match_value == risk_level

        if not is_match:
            continue

        text = str(rule["recommendation_text"]).strip()
        text_key = text.lower()

        if not text or text_key in existing_texts:
            continue

        result["recommendations"].append(
            {
                "priority": rule["priority"],
                "category": rule["category"],
                "recommendation_text": text,
                "reason": f"Matched {match_type} signal: {match_value}.",
                "related_technique_id": match_value if match_type == "MITRE" else None,
            }
        )

        existing_texts.add(text_key)

    return result


def normalize_agent_result(result: Dict[str, Any]) -> Dict[str, Any]:
    risk_levels = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    confidence_levels = {"LOW", "MEDIUM", "HIGH"}

    entity_types = {
        "ACTOR",
        "MALWARE",
        "CAMPAIGN",
        "INDUSTRY",
        "COUNTRY",
        "ATTACK_TYPE",
        "TOOL",
        "ORGANIZATION",
    }

    indicator_types = {
        "IP",
        "DOMAIN",
        "URL",
        "HASH",
        "EMAIL",
        "FILE",
        "REGISTRY",
    }

    indicator_sources = {
        "AI_EXTRACTED",
        "REGEX_EXTRACTED",
        "API_ENRICHED",
    }

    malicious_values = {"YES", "NO", "UNKNOWN"}
    cve_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    recommendation_priorities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    recommendation_categories = {
        "BLOCKING",
        "DETECTION",
        "PATCHING",
        "MONITORING",
        "USER_AWARENESS",
        "ACCESS_CONTROL",
        "INCIDENT_RESPONSE",
    }

    normalized = {
        "executive_summary": result.get("executive_summary") or "No executive summary generated.",
        "risk_score": max(0, min(100, _safe_number(result.get("risk_score"), 50))),
        "risk_level": _normalize_choice(result.get("risk_level"), risk_levels, "MEDIUM"),
        "confidence_score": max(0, min(100, _safe_number(result.get("confidence_score"), 70))),
        "threat_entities": [],
        "indicators": [],
        "cves": [],
        "mitre_techniques": [],
        "attack_chain_steps": [],
        "recommendations": [],
        "evidence_findings": [],
        "final_report": result.get("final_report") or "No final report generated.",
    }

    for item in _as_list(result.get("threat_entities")):
        if not isinstance(item, dict):
            continue

        entity_value = item.get("entity_value")

        if not entity_value:
            continue

        normalized["threat_entities"].append(
            {
                "entity_type": _normalize_choice(item.get("entity_type"), entity_types, "ATTACK_TYPE"),
                "entity_value": str(entity_value)[:255],
                "description": item.get("description") or "",
                "confidence": _normalize_choice(item.get("confidence"), confidence_levels, "MEDIUM"),
                "evidence_text": item.get("evidence_text") or "",
            }
        )

    for item in _as_list(result.get("indicators")):
        if not isinstance(item, dict):
            continue

        indicator_value = item.get("indicator_value")

        if not indicator_value:
            continue

        normalized["indicators"].append(
            {
                "indicator_type": _normalize_choice(item.get("indicator_type"), indicator_types, "DOMAIN"),
                "indicator_value": str(indicator_value)[:1000],
                "description": item.get("description") or "",
                "confidence": _normalize_choice(item.get("confidence"), confidence_levels, "MEDIUM"),
                "source": _normalize_choice(item.get("source"), indicator_sources, "AI_EXTRACTED"),
                "is_malicious": _normalize_choice(item.get("is_malicious"), malicious_values, "UNKNOWN"),
                "evidence_text": item.get("evidence_text") or "",
            }
        )

    for item in _as_list(result.get("cves")):
        if not isinstance(item, dict):
            continue

        cve_id = item.get("cve_id")

        if not cve_id:
            continue

        cvss_score = item.get("cvss_score")

        if cvss_score is not None:
            cvss_score = max(0, min(10, _safe_number(cvss_score, 0)))

        normalized["cves"].append(
            {
                "cve_id": str(cve_id)[:30],
                "severity": _normalize_choice(item.get("severity"), cve_severities, "UNKNOWN"),
                "cvss_score": cvss_score,
                "affected_product": item.get("affected_product"),
                "context": item.get("context") or "",
                "evidence_text": item.get("evidence_text") or "",
            }
        )

    for item in _as_list(result.get("mitre_techniques")):
        if not isinstance(item, dict):
            continue

        technique_id = item.get("technique_id")
        technique_name = item.get("technique_name")

        if not technique_id or not technique_name:
            continue

        normalized["mitre_techniques"].append(
            {
                "technique_id": str(technique_id)[:30],
                "technique_name": str(technique_name)[:255],
                "tactic": item.get("tactic") or "",
                "description": item.get("description") or "",
                "confidence": _normalize_choice(item.get("confidence"), confidence_levels, "MEDIUM"),
                "evidence_text": item.get("evidence_text") or "",
            }
        )

    for index, item in enumerate(_as_list(result.get("attack_chain_steps")), start=1):
        if not isinstance(item, dict):
            continue

        step_title = item.get("step_title")

        if not step_title:
            continue

        related_technique_id = item.get("related_technique_id")

        if related_technique_id:
            related_technique_id = str(related_technique_id)[:30]

        normalized["attack_chain_steps"].append(
            {
                "step_order": _safe_int(item.get("step_order"), index),
                "phase_name": item.get("phase_name") or "",
                "step_title": str(step_title)[:255],
                "step_description": item.get("step_description") or "",
                "related_technique_id": related_technique_id,
                "evidence_text": item.get("evidence_text") or "",
            }
        )

    for item in _as_list(result.get("recommendations")):
        if not isinstance(item, dict):
            continue

        recommendation_text = item.get("recommendation_text")

        if not recommendation_text:
            continue

        related_technique_id = item.get("related_technique_id")

        if related_technique_id:
            related_technique_id = str(related_technique_id)[:30]

        normalized["recommendations"].append(
            {
                "priority": _normalize_choice(item.get("priority"), recommendation_priorities, "MEDIUM"),
                "category": _normalize_choice(item.get("category"), recommendation_categories, "MONITORING"),
                "recommendation_text": recommendation_text,
                "reason": item.get("reason") or "",
                "related_technique_id": related_technique_id,
            }
        )

    for item in _as_list(result.get("evidence_findings")):
        if not isinstance(item, dict):
            continue

        finding_title = item.get("finding_title")

        if not finding_title:
            continue

        normalized["evidence_findings"].append(
            {
                "finding_title": str(finding_title)[:255],
                "finding_description": item.get("finding_description") or "",
                "severity": _normalize_choice(item.get("severity"), recommendation_priorities, "MEDIUM"),
                "confidence": _normalize_choice(item.get("confidence"), confidence_levels, "MEDIUM"),
                "evidence_text": item.get("evidence_text") or "",
                "agent_name": item.get("agent_name") or "ThreatIntel Agent",
            }
        )

    return normalized


def run_analysis_pipeline(
    title: str,
    source_type: Literal["TEXT", "URL", "PDF"],
    raw_content: str,
    user_id: int,
    source_url: Optional[str] = None,
    original_file_name: Optional[str] = None,
):
    analysis_id = None

    try:
        analysis_id = create_analysis_row(
            title=title,
            source_type=source_type,
            raw_content=raw_content,
            user_id=user_id,
            source_url=source_url,
            original_file_name=original_file_name,
            status="PROCESSING",
        )

        insert_agent_step(
            analysis_id=analysis_id,
            agent_name="Ingestion Agent",
            step_order=1,
            status="COMPLETED",
            input_summary=f"Received {source_type} source from user.",
            output_summary="Extracted and prepared report content for analysis.",
            output_json={
                "source_type": source_type,
                "input_length": len(raw_content),
                "source_url": source_url,
                "original_file_name": original_file_name,
            },
        )

        raw_result = run_threatintel_agent(raw_content)
        raw_result = enrich_with_mitre_reference(raw_result)
        raw_result = append_rule_based_recommendations(raw_result)
        result = normalize_agent_result(raw_result)

        insert_agent_step(
            analysis_id=analysis_id,
            agent_name="ThreatIntel Agent",
            step_order=2,
            status="COMPLETED",
            input_summary="Submitted report content to the AI analysis workflow.",
            output_summary="Generated structured threat intelligence output.",
            output_json={"agent_mode": "ai_or_fallback"},
        )

        insert_agent_step(
            analysis_id=analysis_id,
            agent_name="Entity Extraction Agent",
            step_order=3,
            status="COMPLETED",
            input_summary="Reviewed report for threat entities, indicators, and CVEs.",
            output_summary=(
                f"Found {len(result.get('threat_entities', []))} threat entities, "
                f"{len(result.get('indicators', []))} indicators, "
                f"{len(result.get('cves', []))} CVEs."
            ),
            output_json={
                "threat_entities": len(result.get("threat_entities", [])),
                "indicators": len(result.get("indicators", [])),
                "cves": len(result.get("cves", [])),
            },
        )

        insert_agent_step(
            analysis_id=analysis_id,
            agent_name="MITRE Mapping Agent",
            step_order=4,
            status="COMPLETED",
            input_summary="Mapped observed behavior to MITRE ATT&CK techniques.",
            output_summary=f"Mapped {len(result.get('mitre_techniques', []))} MITRE techniques.",
            output_json={"mitre_count": len(result.get("mitre_techniques", []))},
        )

        insert_agent_step(
            analysis_id=analysis_id,
            agent_name="Risk Scoring Agent",
            step_order=5,
            status="COMPLETED",
            input_summary="Calculated severity and confidence.",
            output_summary=(
                f"Risk level: {result.get('risk_level')} | "
                f"Risk score: {result.get('risk_score')}"
            ),
            output_json={
                "risk_score": result.get("risk_score"),
                "risk_level": result.get("risk_level"),
                "confidence_score": result.get("confidence_score"),
            },
        )

        insert_agent_step(
            analysis_id=analysis_id,
            agent_name="Report Generation Agent",
            step_order=6,
            status="COMPLETED",
            input_summary="Generated analyst-ready intelligence brief.",
            output_summary="Final threat intelligence brief generated.",
            output_json={"report_generated": True},
        )

        save_threatintel_result(analysis_id, result)

        return {
            "status": "ok",
            "message": f"{source_type} analysis completed successfully",
            "analysis_id": analysis_id,
            "risk_level": result.get("risk_level"),
            "risk_score": result.get("risk_score"),
        }

    except Exception as error:
        if analysis_id:
            mark_analysis_failed(analysis_id, str(error))

        raise HTTPException(status_code=500, detail=str(error))


def _md_value(value):
    if value is None:
        return "N/A"

    return str(value).replace("|", "\\|").replace("\n", " ")


def _markdown_table(headers, rows):
    if not rows:
        return "_No data found._\n"

    output = []
    output.append("| " + " | ".join(headers) + " |")
    output.append("| " + " | ".join(["---"] * len(headers)) + " |")

    for row in rows:
        output.append("| " + " | ".join(_md_value(row.get(header)) for header in headers) + " |")

    return "\n".join(output) + "\n"


def build_markdown_export(analysis):
    lines = []

    lines.append(f"# {analysis.get('title', 'Threat Intelligence Report')}")
    lines.append("")
    lines.append(f"**Analysis ID:** {analysis.get('analysis_id')}")
    lines.append(f"**Source Type:** {analysis.get('source_type')}")
    lines.append(f"**Status:** {analysis.get('status')}")
    lines.append(f"**Risk Level:** {analysis.get('risk_level') or 'N/A'}")
    lines.append(f"**Risk Score:** {analysis.get('risk_score') or 'N/A'}")
    lines.append(f"**Confidence Score:** {analysis.get('confidence_score') or 'N/A'}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append(analysis.get("executive_summary") or "No executive summary available.")
    lines.append("")

    lines.append("## Agent Trace")
    lines.append(
        _markdown_table(
            ["step_order", "agent_name", "status", "output_summary"],
            analysis.get("agent_steps", []),
        )
    )

    lines.append("## Threat Entities")
    lines.append(
        _markdown_table(
            ["entity_type", "entity_value", "confidence"],
            analysis.get("threat_entities", []),
        )
    )

    lines.append("## Indicators of Compromise")
    lines.append(
        _markdown_table(
            ["indicator_type", "indicator_value", "is_malicious", "confidence"],
            analysis.get("indicators", []),
        )
    )

    lines.append("## CVEs")
    lines.append(
        _markdown_table(
            ["cve_id", "severity", "cvss_score", "affected_product"],
            analysis.get("cves", []),
        )
    )

    lines.append("## MITRE ATT&CK Mapping")
    lines.append(
        _markdown_table(
            ["technique_id", "technique_name", "tactic", "confidence"],
            analysis.get("mitre_techniques", []),
        )
    )

    lines.append("## Attack Chain")
    lines.append(
        _markdown_table(
            ["step_order", "phase_name", "step_title", "related_technique_id"],
            analysis.get("attack_chain_steps", []),
        )
    )

    lines.append("## Recommendations")
    lines.append(
        _markdown_table(
            ["priority", "category", "recommendation_text", "reason"],
            analysis.get("recommendations", []),
        )
    )

    lines.append("## Evidence-backed Findings")
    lines.append(
        _markdown_table(
            ["finding_title", "severity", "confidence", "evidence_text"],
            analysis.get("evidence_findings", []),
        )
    )

    lines.append("## Final Analyst Report")
    lines.append(analysis.get("final_report") or "No final report available.")
    lines.append("")

    return "\n".join(lines)


@app.get("/")
def root():
    return {
        "message": "ThreatIntel Agent Backend is running",
    }


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "backend",
        "message": "ThreatIntel Agent API is working",
    }


@app.get("/db-test")
def db_test():
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM USERS")
        users_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM MITRE_TECHNIQUE_REF")
        mitre_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM RECOMMENDATION_RULES")
        rules_count = cursor.fetchone()[0]

        return {
            "status": "ok",
            "database": "connected",
            "users": users_count,
            "mitre_techniques": mitre_count,
            "recommendation_rules": rules_count,
        }

    except Exception as error:
        return {
            "status": "error",
            "database": "connection_failed",
            "error": str(error),
        }

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.post("/analysis/create")
def create_analysis(payload: CreateAnalysisRequest):
    try:
        resolved_user_id = resolve_user_id(payload.user_id, payload.client_id)

        analysis_id = create_analysis_row(
            title=payload.title,
            source_type=payload.source_type,
            raw_content=payload.raw_content,
            user_id=resolved_user_id,
            source_url=payload.source_url,
            original_file_name=payload.original_file_name,
            status="COMPLETED",
        )

        insert_agent_step(
            analysis_id=analysis_id,
            agent_name="Ingestion Agent",
            step_order=1,
            status="COMPLETED",
            input_summary="Received manual analysis input.",
            output_summary="Saved submitted content.",
            output_json={"mode": "manual_save"},
        )

        return {
            "status": "ok",
            "message": "Analysis created successfully",
            "analysis_id": analysis_id,
        }

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.post("/analysis/analyze-text")
def analyze_text(payload: TextAnalysisRequest):
    resolved_user_id = resolve_user_id(payload.user_id, payload.client_id)

    return run_analysis_pipeline(
        title=payload.title,
        source_type="TEXT",
        raw_content=payload.raw_content,
        user_id=resolved_user_id,
    )


@app.post("/analysis/analyze-url")
def analyze_url(payload: UrlAnalysisRequest):
    resolved_user_id = resolve_user_id(payload.user_id, payload.client_id)

    try:
        extracted_text = extract_text_from_url(payload.url)
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error))

    return run_analysis_pipeline(
        title=payload.title,
        source_type="URL",
        raw_content=extracted_text,
        user_id=resolved_user_id,
        source_url=payload.url,
    )


@app.post("/analysis/analyze-pdf")
async def analyze_pdf(
    title: str = Form(...),
    user_id: int = Form(1),
    client_id: Optional[str] = Form(None),
    file: UploadFile = File(...),
):
    resolved_user_id = resolve_user_id(user_id, client_id)

    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")

    try:
        pdf_bytes = await file.read()
        extracted_text = extract_text_from_pdf_bytes(pdf_bytes)
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error))

    return run_analysis_pipeline(
        title=title,
        source_type="PDF",
        raw_content=extracted_text,
        user_id=resolved_user_id,
        original_file_name=file.filename,
    )


@app.get("/analysis")
def get_analyses(
    client_id: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
):
    try:
        resolved_user_id = resolve_user_id(user_id, client_id)
        analyses = list_user_analyses(resolved_user_id)

        return {
            "status": "ok",
            "count": len(analyses),
            "analyses": analyses,
        }

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.get("/analysis/{analysis_id}")
def get_analysis(
    analysis_id: int,
    client_id: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
):
    try:
        resolved_user_id = resolve_user_id(user_id, client_id)
        analysis = get_user_analysis_detail(analysis_id, resolved_user_id)

        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")

        return {
            "status": "ok",
            "analysis": analysis,
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.get("/analysis/{analysis_id}/export/markdown")
def export_analysis_markdown(
    analysis_id: int,
    client_id: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
):
    try:
        resolved_user_id = resolve_user_id(user_id, client_id)
        analysis = get_user_analysis_detail(analysis_id, resolved_user_id)

        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")

        markdown = build_markdown_export(analysis)

        return PlainTextResponse(
            markdown,
            media_type="text/markdown",
        )

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))