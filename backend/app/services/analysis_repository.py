import json
from typing import Any, Dict, List, Optional
import re
import oracledb

from app.database import get_connection


def _lob_to_text(value):
    if isinstance(value, oracledb.LOB):
        return value.read()
    return value


def _row_to_dict(cursor, row):
    columns = [col[0].lower() for col in cursor.description]
    result = {}

    for index, value in enumerate(row):
        result[columns[index]] = _lob_to_text(value)

    return result


def _get_returned_id(return_var) -> int:
    value = return_var.getvalue()
    if isinstance(value, list):
        return int(value[0])
    return int(value)

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
            {"email": guest_email}
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
                "password_hash": "GUEST_SESSION_NO_PASSWORD",
                "user_id": user_id_var,
            }
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
            {"email": guest_email}
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

def create_analysis_row(
    title: str,
    source_type: str,
    raw_content: str,
    user_id: int = 1,
    source_url: Optional[str] = None,
    original_file_name: Optional[str] = None,
    status: str = "PROCESSING"
) -> int:
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        analysis_id_var = cursor.var(oracledb.NUMBER)

        cursor.execute(
            """
            INSERT INTO ANALYSES (
                USER_ID,
                TITLE,
                SOURCE_TYPE,
                SOURCE_URL,
                ORIGINAL_FILE_NAME,
                RAW_CONTENT,
                CLEANED_CONTENT,
                STATUS,
                CREATED_AT,
                UPDATED_AT
            )
            VALUES (
                :user_id,
                :title,
                :source_type,
                :source_url,
                :original_file_name,
                :raw_content,
                :cleaned_content,
                :status,
                SYSTIMESTAMP,
                SYSTIMESTAMP
            )
            RETURNING ANALYSIS_ID INTO :analysis_id
            """,
            {
                "user_id": user_id,
                "title": title,
                "source_type": source_type,
                "source_url": source_url,
                "original_file_name": original_file_name,
                "raw_content": raw_content,
                "cleaned_content": raw_content.strip(),
                "status": status,
                "analysis_id": analysis_id_var,
            }
        )

        connection.commit()
        return _get_returned_id(analysis_id_var)

    except Exception:
        if connection:
            connection.rollback()
        raise

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def insert_agent_step(
    analysis_id: int,
    agent_name: str,
    step_order: int,
    status: str,
    input_summary: str,
    output_summary: str,
    output_json: Optional[Dict[str, Any]] = None
):
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO AGENT_STEPS (
                ANALYSIS_ID,
                AGENT_NAME,
                STEP_ORDER,
                STATUS,
                INPUT_SUMMARY,
                OUTPUT_SUMMARY,
                OUTPUT_JSON,
                STARTED_AT,
                COMPLETED_AT,
                CREATED_AT
            )
            VALUES (
                :analysis_id,
                :agent_name,
                :step_order,
                :status,
                :input_summary,
                :output_summary,
                :output_json,
                SYSTIMESTAMP,
                SYSTIMESTAMP,
                SYSTIMESTAMP
            )
            """,
            {
                "analysis_id": analysis_id,
                "agent_name": agent_name,
                "step_order": step_order,
                "status": status,
                "input_summary": input_summary,
                "output_summary": output_summary,
                "output_json": json.dumps(output_json or {}, ensure_ascii=False),
            }
        )

        connection.commit()

    except Exception:
        if connection:
            connection.rollback()
        raise

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def save_threatintel_result(analysis_id: int, result: Dict[str, Any]):
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE ANALYSES
            SET
                STATUS = 'COMPLETED',
                RISK_SCORE = :risk_score,
                RISK_LEVEL = :risk_level,
                CONFIDENCE_SCORE = :confidence_score,
                EXECUTIVE_SUMMARY = :executive_summary,
                FINAL_REPORT = :final_report,
                UPDATED_AT = SYSTIMESTAMP
            WHERE ANALYSIS_ID = :analysis_id
            """,
            {
                "risk_score": result.get("risk_score"),
                "risk_level": result.get("risk_level"),
                "confidence_score": result.get("confidence_score"),
                "executive_summary": result.get("executive_summary"),
                "final_report": result.get("final_report"),
                "analysis_id": analysis_id,
            }
        )

        for item in result.get("threat_entities", []):
            cursor.execute(
                """
                INSERT INTO THREAT_ENTITIES (
                    ANALYSIS_ID,
                    ENTITY_TYPE,
                    ENTITY_VALUE,
                    DESCRIPTION,
                    CONFIDENCE,
                    EVIDENCE_TEXT,
                    CREATED_AT
                )
                VALUES (
                    :analysis_id,
                    :entity_type,
                    :entity_value,
                    :description,
                    :confidence,
                    :evidence_text,
                    SYSTIMESTAMP
                )
                """,
                {
                    "analysis_id": analysis_id,
                    "entity_type": item.get("entity_type"),
                    "entity_value": item.get("entity_value"),
                    "description": item.get("description"),
                    "confidence": item.get("confidence"),
                    "evidence_text": item.get("evidence_text"),
                }
            )

        for item in result.get("indicators", []):
            cursor.execute(
                """
                INSERT INTO INDICATORS (
                    ANALYSIS_ID,
                    INDICATOR_TYPE,
                    INDICATOR_VALUE,
                    DESCRIPTION,
                    CONFIDENCE,
                    SOURCE,
                    IS_MALICIOUS,
                    EVIDENCE_TEXT,
                    CREATED_AT
                )
                VALUES (
                    :analysis_id,
                    :indicator_type,
                    :indicator_value,
                    :description,
                    :confidence,
                    :source,
                    :is_malicious,
                    :evidence_text,
                    SYSTIMESTAMP
                )
                """,
                {
                    "analysis_id": analysis_id,
                    "indicator_type": item.get("indicator_type"),
                    "indicator_value": item.get("indicator_value"),
                    "description": item.get("description"),
                    "confidence": item.get("confidence"),
                    "source": item.get("source", "AI_EXTRACTED"),
                    "is_malicious": item.get("is_malicious", "UNKNOWN"),
                    "evidence_text": item.get("evidence_text"),
                }
            )

        for item in result.get("cves", []):
            cursor.execute(
                """
                INSERT INTO CVES (
                    ANALYSIS_ID,
                    CVE_ID,
                    SEVERITY,
                    CVSS_SCORE,
                    AFFECTED_PRODUCT,
                    CONTEXT,
                    EVIDENCE_TEXT,
                    CREATED_AT
                )
                VALUES (
                    :analysis_id,
                    :cve_id,
                    :severity,
                    :cvss_score,
                    :affected_product,
                    :context,
                    :evidence_text,
                    SYSTIMESTAMP
                )
                """,
                {
                    "analysis_id": analysis_id,
                    "cve_id": item.get("cve_id"),
                    "severity": item.get("severity"),
                    "cvss_score": item.get("cvss_score"),
                    "affected_product": item.get("affected_product"),
                    "context": item.get("context"),
                    "evidence_text": item.get("evidence_text"),
                }
            )

        for item in result.get("mitre_techniques", []):
            cursor.execute(
                """
                INSERT INTO MITRE_TECHNIQUES (
                    ANALYSIS_ID,
                    TECHNIQUE_ID,
                    TECHNIQUE_NAME,
                    TACTIC,
                    DESCRIPTION,
                    CONFIDENCE,
                    EVIDENCE_TEXT,
                    CREATED_AT
                )
                VALUES (
                    :analysis_id,
                    :technique_id,
                    :technique_name,
                    :tactic,
                    :description,
                    :confidence,
                    :evidence_text,
                    SYSTIMESTAMP
                )
                """,
                {
                    "analysis_id": analysis_id,
                    "technique_id": item.get("technique_id"),
                    "technique_name": item.get("technique_name"),
                    "tactic": item.get("tactic"),
                    "description": item.get("description"),
                    "confidence": item.get("confidence"),
                    "evidence_text": item.get("evidence_text"),
                }
            )

        for item in result.get("attack_chain_steps", []):
            cursor.execute(
                """
                INSERT INTO ATTACK_CHAIN_STEPS (
                    ANALYSIS_ID,
                    STEP_ORDER,
                    PHASE_NAME,
                    STEP_TITLE,
                    STEP_DESCRIPTION,
                    RELATED_TECHNIQUE_ID,
                    EVIDENCE_TEXT,
                    CREATED_AT
                )
                VALUES (
                    :analysis_id,
                    :step_order,
                    :phase_name,
                    :step_title,
                    :step_description,
                    :related_technique_id,
                    :evidence_text,
                    SYSTIMESTAMP
                )
                """,
                {
                    "analysis_id": analysis_id,
                    "step_order": item.get("step_order"),
                    "phase_name": item.get("phase_name"),
                    "step_title": item.get("step_title"),
                    "step_description": item.get("step_description"),
                    "related_technique_id": item.get("related_technique_id"),
                    "evidence_text": item.get("evidence_text"),
                }
            )

        for item in result.get("recommendations", []):
            cursor.execute(
                """
                INSERT INTO RECOMMENDATIONS (
                    ANALYSIS_ID,
                    PRIORITY,
                    CATEGORY,
                    RECOMMENDATION_TEXT,
                    REASON,
                    RELATED_TECHNIQUE_ID,
                    CREATED_AT
                )
                VALUES (
                    :analysis_id,
                    :priority,
                    :category,
                    :recommendation_text,
                    :reason,
                    :related_technique_id,
                    SYSTIMESTAMP
                )
                """,
                {
                    "analysis_id": analysis_id,
                    "priority": item.get("priority"),
                    "category": item.get("category"),
                    "recommendation_text": item.get("recommendation_text"),
                    "reason": item.get("reason"),
                    "related_technique_id": item.get("related_technique_id"),
                }
            )

        for item in result.get("evidence_findings", []):
            cursor.execute(
                """
                INSERT INTO EVIDENCE_FINDINGS (
                    ANALYSIS_ID,
                    FINDING_TITLE,
                    FINDING_DESCRIPTION,
                    SEVERITY,
                    CONFIDENCE,
                    EVIDENCE_TEXT,
                    AGENT_NAME,
                    CREATED_AT
                )
                VALUES (
                    :analysis_id,
                    :finding_title,
                    :finding_description,
                    :severity,
                    :confidence,
                    :evidence_text,
                    :agent_name,
                    SYSTIMESTAMP
                )
                """,
                {
                    "analysis_id": analysis_id,
                    "finding_title": item.get("finding_title"),
                    "finding_description": item.get("finding_description"),
                    "severity": item.get("severity"),
                    "confidence": item.get("confidence"),
                    "evidence_text": item.get("evidence_text"),
                    "agent_name": item.get("agent_name"),
                }
            )

        connection.commit()

    except Exception:
        if connection:
            connection.rollback()
        raise

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def mark_analysis_failed(analysis_id: int, error_message: str):
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE ANALYSES
            SET
                STATUS = 'FAILED',
                ERROR_MESSAGE = :error_message,
                UPDATED_AT = SYSTIMESTAMP
            WHERE ANALYSIS_ID = :analysis_id
            """,
            {
                "analysis_id": analysis_id,
                "error_message": error_message
            }
        )

        connection.commit()

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def list_analyses(user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        query = """
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
        """

        params = {}

        if user_id is not None:
            query += " WHERE USER_ID = :user_id "
            params["user_id"] = user_id

        query += " ORDER BY CREATED_AT DESC "

        cursor.execute(query, params)

        return [_row_to_dict(cursor, row) for row in cursor.fetchall()]

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def fetch_table_rows(table_name: str, analysis_id: int) -> List[Dict[str, Any]]:
    allowed_tables = {
        "AGENT_STEPS",
        "THREAT_ENTITIES",
        "INDICATORS",
        "CVES",
        "MITRE_TECHNIQUES",
        "ATTACK_CHAIN_STEPS",
        "RECOMMENDATIONS",
        "EVIDENCE_FINDINGS"
    }

    if table_name not in allowed_tables:
        raise ValueError("Invalid table name")

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
            ORDER BY CREATED_AT
            """,
            {"analysis_id": analysis_id}
        )

        return [_row_to_dict(cursor, row) for row in cursor.fetchall()]

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def get_analysis_detail(analysis_id: int, user_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
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
            AND (:user_id IS NULL OR USER_ID = :user_id)
            """,
            {
                "analysis_id": analysis_id,
                "user_id": user_id
            }
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

    analysis["agent_steps"] = fetch_table_rows("AGENT_STEPS", analysis_id)
    analysis["threat_entities"] = fetch_table_rows("THREAT_ENTITIES", analysis_id)
    analysis["indicators"] = fetch_table_rows("INDICATORS", analysis_id)
    analysis["cves"] = fetch_table_rows("CVES", analysis_id)
    analysis["mitre_techniques"] = fetch_table_rows("MITRE_TECHNIQUES", analysis_id)
    analysis["attack_chain_steps"] = fetch_table_rows("ATTACK_CHAIN_STEPS", analysis_id)
    analysis["recommendations"] = fetch_table_rows("RECOMMENDATIONS", analysis_id)
    analysis["evidence_findings"] = fetch_table_rows("EVIDENCE_FINDINGS", analysis_id)

    return analysis