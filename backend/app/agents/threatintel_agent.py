import json
import os
from typing import Any, Dict

from dotenv import load_dotenv

load_dotenv()


def _safe_json_loads(text: str) -> Dict[str, Any]:
    cleaned = text.strip()

    if cleaned.startswith("```json"):
        cleaned = cleaned.replace("```json", "", 1).strip()

    if cleaned.startswith("```"):
        cleaned = cleaned.replace("```", "", 1).strip()

    if cleaned.endswith("```"):
        cleaned = cleaned[:-3].strip()

    return json.loads(cleaned)


def _mock_threatintel_result(report_text: str) -> Dict[str, Any]:
    return {
        "executive_summary": (
            "This report appears to describe suspicious cyber activity involving "
            "phishing-style behavior, malicious infrastructure, and possible credential risk."
        ),
        "risk_score": 76,
        "risk_level": "HIGH",
        "confidence_score": 82,
        "threat_entities": [
            {
                "entity_type": "ATTACK_TYPE",
                "entity_value": "Phishing",
                "description": "The report text suggests phishing or social engineering behavior.",
                "confidence": "MEDIUM",
                "evidence_text": report_text[:300]
            }
        ],
        "indicators": [],
        "cves": [],
        "mitre_techniques": [
            {
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "tactic": "Initial Access",
                "description": "Possible phishing behavior based on the report content.",
                "confidence": "MEDIUM",
                "evidence_text": report_text[:300]
            }
        ],
        "attack_chain_steps": [
            {
                "step_order": 1,
                "phase_name": "Initial Access",
                "step_title": "Suspicious initial access activity",
                "step_description": "The report indicates possible phishing or malicious delivery activity.",
                "related_technique_id": "T1566",
                "evidence_text": report_text[:300]
            }
        ],
        "recommendations": [
            {
                "priority": "HIGH",
                "category": "USER_AWARENESS",
                "recommendation_text": "Review email security controls and train users to report suspicious messages.",
                "reason": "The report suggests possible phishing behavior.",
                "related_technique_id": "T1566"
            }
        ],
        "evidence_findings": [
            {
                "finding_title": "Possible phishing behavior detected",
                "finding_description": "The submitted report appears to describe phishing-style behavior.",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "evidence_text": report_text[:300],
                "agent_name": "ThreatIntel Agent"
            }
        ],
        "final_report": (
            "ThreatIntel Agent generated a preliminary intelligence brief. "
            "The report indicates possible phishing behavior and recommends reviewing email security, "
            "monitoring suspicious domains or URLs, and validating user account activity."
        )
    }


def build_threatintel_prompt(report_text: str) -> str:
    return f"""
You are ThreatIntel Agent, a defensive cybersecurity intelligence analyst.

Analyze the submitted cyber threat report and return ONLY valid JSON.
Do not include markdown. Do not include explanations outside JSON.

Your JSON must follow this exact structure:

{{
  "executive_summary": "string",
  "risk_score": number_between_0_and_100,
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "confidence_score": number_between_0_and_100,
  "threat_entities": [
    {{
      "entity_type": "ACTOR | MALWARE | CAMPAIGN | INDUSTRY | COUNTRY | ATTACK_TYPE | TOOL | ORGANIZATION",
      "entity_value": "string",
      "description": "string",
      "confidence": "LOW | MEDIUM | HIGH",
      "evidence_text": "short exact evidence from report"
    }}
  ],
  "indicators": [
    {{
      "indicator_type": "IP | DOMAIN | URL | HASH | EMAIL | FILE | REGISTRY",
      "indicator_value": "string",
      "description": "string",
      "confidence": "LOW | MEDIUM | HIGH",
      "source": "AI_EXTRACTED",
      "is_malicious": "YES | NO | UNKNOWN",
      "evidence_text": "short exact evidence from report"
    }}
  ],
  "cves": [
    {{
      "cve_id": "CVE-YYYY-NNNN",
      "severity": "LOW | MEDIUM | HIGH | CRITICAL | UNKNOWN",
      "cvss_score": null,
      "affected_product": "string or null",
      "context": "string",
      "evidence_text": "short exact evidence from report"
    }}
  ],
  "mitre_techniques": [
    {{
      "technique_id": "Txxxx or Txxxx.xxx",
      "technique_name": "string",
      "tactic": "string",
      "description": "string",
      "confidence": "LOW | MEDIUM | HIGH",
      "evidence_text": "short exact evidence from report"
    }}
  ],
  "attack_chain_steps": [
    {{
      "step_order": 1,
      "phase_name": "string",
      "step_title": "string",
      "step_description": "string",
      "related_technique_id": "string or null",
      "evidence_text": "short exact evidence from report"
    }}
  ],
  "recommendations": [
    {{
      "priority": "LOW | MEDIUM | HIGH | CRITICAL",
      "category": "BLOCKING | DETECTION | PATCHING | MONITORING | USER_AWARENESS | ACCESS_CONTROL | INCIDENT_RESPONSE",
      "recommendation_text": "string",
      "reason": "string",
      "related_technique_id": "string or null"
    }}
  ],
  "evidence_findings": [
    {{
      "finding_title": "string",
      "finding_description": "string",
      "severity": "LOW | MEDIUM | HIGH | CRITICAL",
      "confidence": "LOW | MEDIUM | HIGH",
      "evidence_text": "short exact evidence from report",
      "agent_name": "string"
    }}
  ],
  "final_report": "full analyst-style threat intelligence brief"
}}

Rules:
- Use defensive cybersecurity language only.
- Do not provide exploit instructions or offensive steps.
- If a section has no data, return an empty array.
- Evidence text must be copied or closely grounded from the submitted report.
- Keep all values concise and database-safe.

Submitted report:
\"\"\"
{report_text[:12000]}
\"\"\"
"""


def run_threatintel_agent(report_text: str) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    if not api_key:
        return _mock_threatintel_result(report_text)

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)

        prompt = build_threatintel_prompt(report_text)

        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,
                response_mime_type="application/json"
            )
        )

        return _safe_json_loads(response.text)

    except Exception as error:
        fallback = _mock_threatintel_result(report_text)
        fallback["executive_summary"] = (
            "AI provider call failed, so ThreatIntel Agent returned a local fallback analysis."
        )
        fallback["final_report"] = f"AI provider error: {str(error)}"
        return fallback