from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import get_connection

app = FastAPI(
    title="ThreatIntel Agent API",
    description="Backend API for ThreatIntel Agent",
    version="1.0.0"
)

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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