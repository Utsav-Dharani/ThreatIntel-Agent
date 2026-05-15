from typing import Optional, Literal

import oracledb
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.database import get_connection


app = FastAPI(
    title="ThreatIntel Agent API",
    description="Backend API for ThreatIntel Agent",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
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


def row_to_dict(cursor, row):
    columns = [col[0].lower() for col in cursor.description]
    result = {}

    for index, value in enumerate(row):
        if isinstance(value, oracledb.LOB):
            value = value.read()

        result[columns[index]] = value

    return result


@app.get("/")
def root():
    return {
        "message": "ThreatIntel Agent Backend is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "backend",
        "message": "FastAPI backend is working"
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
            "recommendation_rules": rules_count
        }

    except Exception as error:
        return {
            "status": "error",
            "database": "connection_failed",
            "error": str(error)
        }

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.post("/analysis/create")
def create_analysis(payload: CreateAnalysisRequest):
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
                EXECUTIVE_SUMMARY,
                FINAL_REPORT,
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
                'COMPLETED',
                :executive_summary,
                :final_report,
                SYSTIMESTAMP,
                SYSTIMESTAMP
            )
            RETURNING ANALYSIS_ID INTO :analysis_id
            """,
            {
                "user_id": payload.user_id or 1,
                "title": payload.title,
                "source_type": payload.source_type,
                "source_url": payload.source_url,
                "original_file_name": payload.original_file_name,
                "raw_content": payload.raw_content,
                "cleaned_content": payload.raw_content.strip(),
                "executive_summary": "Analysis saved successfully. AI processing will be added in the next phase.",
                "final_report": "This is a saved analysis placeholder. AI-generated threat intelligence report will be added later.",
                "analysis_id": analysis_id_var,
            }
        )

        connection.commit()

        analysis_id_value = analysis_id_var.getvalue()
        if isinstance(analysis_id_value, list):
            analysis_id = int(analysis_id_value[0])
        else:
            analysis_id = int(analysis_id_value)

        return {
            "status": "ok",
            "message": "Analysis created successfully",
            "analysis_id": analysis_id
        }

    except Exception as error:
        if connection:
            connection.rollback()

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.get("/analysis")
def list_analyses():
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
            ORDER BY CREATED_AT DESC
            """
        )

        rows = cursor.fetchall()

        analyses = []
        for row in rows:
            analyses.append(row_to_dict(cursor, row))

        return {
            "status": "ok",
            "count": len(analyses),
            "analyses": analyses
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.get("/analysis/{analysis_id}")
def get_analysis(analysis_id: int):
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
            """,
            {
                "analysis_id": analysis_id
            }
        )

        row = cursor.fetchone()

        if not row:
            raise HTTPException(
                status_code=404,
                detail="Analysis not found"
            )

        analysis = row_to_dict(cursor, row)

        return {
            "status": "ok",
            "analysis": analysis
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()