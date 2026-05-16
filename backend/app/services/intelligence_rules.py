from typing import Any, Dict, List

import oracledb

from app.database import get_connection


def _lob_to_text(value):
    if isinstance(value, oracledb.LOB):
        return value.read()
    return value


def _fetch_recommendation_rules() -> List[Dict[str, Any]]:
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

        rows = cursor.fetchall()

        rules = []

        for row in rows:
            rules.append({
                "match_type": row[0],
                "match_value": row[1],
                "category": row[2],
                "priority": row[3],
                "recommendation_text": _lob_to_text(row[4]),
            })

        return rules

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def _fetch_mitre_refs() -> Dict[str, Dict[str, Any]]:
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

        rows = cursor.fetchall()

        refs = {}

        for row in rows:
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
    refs = _fetch_mitre_refs()

    for technique in result.get("mitre_techniques", []) or []:
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


def append_rule_based_recommendations(result: Dict[str, Any]) -> Dict[str, Any]:
    result.setdefault("recommendations", [])

    existing_texts = {
        str(item.get("recommendation_text", "")).strip().lower()
        for item in result.get("recommendations", [])
    }

    mitre_ids = {
        str(item.get("technique_id", "")).upper()
        for item in result.get("mitre_techniques", [])
    }

    mitre_base_ids = {
        technique_id.split(".")[0]
        for technique_id in mitre_ids
        if technique_id
    }

    indicator_types = {
        str(item.get("indicator_type", "")).upper()
        for item in result.get("indicators", [])
    }

    cve_severities = {
        str(item.get("severity", "")).upper()
        for item in result.get("cves", [])
    }

    risk_level = str(result.get("risk_level", "")).upper()

    for rule in _fetch_recommendation_rules():
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

        result["recommendations"].append({
            "priority": rule["priority"],
            "category": rule["category"],
            "recommendation_text": text,
            "reason": f"Matched {match_type} signal: {match_value}.",
            "related_technique_id": match_value if match_type == "MITRE" else None
        })

        existing_texts.add(text_key)

    return result