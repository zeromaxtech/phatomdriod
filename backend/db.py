"""
PhantomDroid — Database Layer
MySQL connection and queries for storing
scan sessions, threat history, and reports.
"""

import mysql.connector
import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "localhost"),
    "port": int(os.getenv("MYSQL_PORT", 3306)),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", ""),
    "database": os.getenv("MYSQL_DATABASE", "phantomdroid"),
}


def get_connection():
    return mysql.connector.connect(**DB_CONFIG)


def init_db():
    """Initialize database schema on startup."""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id VARCHAR(36) PRIMARY KEY,
                device_id VARCHAR(100),
                start_time DATETIME,
                end_time DATETIME,
                status VARCHAR(20) DEFAULT 'active',
                threat_count INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session_id VARCHAR(36),
                app VARCHAR(200),
                type VARCHAR(50),
                severity VARCHAR(20),
                description TEXT,
                threat_score INT DEFAULT 0,
                raw_data JSON,
                timestamp DATETIME,
                INDEX idx_session (session_id),
                INDEX idx_severity (severity)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session_id VARCHAR(36),
                report_json JSON,
                pdf_path VARCHAR(500),
                generated_at DATETIME,
                overall_risk VARCHAR(20)
            )
        """)

        conn.commit()
        cursor.close()
        conn.close()
        print("[+] Database initialized")

    except Exception as e:
        print(f"[-] Database init failed: {e}")


def save_event(session_id: str, event: dict):
    """Save a threat event to MySQL."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO threat_events
            (session_id, app, type, severity, description, threat_score, raw_data, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            session_id,
            event.get("app", "unknown"),
            event.get("type", "unknown"),
            event.get("severity", "LOW"),
            event.get("description", ""),
            event.get("threat_score", 0),
            json.dumps(event),
            event.get("timestamp", datetime.now().isoformat())
        ))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[-] DB save error: {e}")


def get_session_data(session_id: str) -> dict:
    """Fetch all data for a session."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM scan_sessions WHERE id = %s", (session_id,))
        session = cursor.fetchone()

        cursor.execute(
            "SELECT * FROM threat_events WHERE session_id = %s ORDER BY timestamp",
            (session_id,)
        )
        events = cursor.fetchall()

        cursor.close()
        conn.close()

        if not session:
            return None

        # Calculate duration
        start = session.get("start_time")
        end = session.get("end_time") or datetime.now()
        duration = int((end - start).total_seconds() / 60) if start else 0

        return {
            "session_id": session_id,
            "device_id": session.get("device_id", "unknown"),
            "duration_minutes": duration,
            "events": [dict(e) for e in events],
            "permissions": [e for e in events if e.get("type") == "permission_scan"],
            "network": [e for e in events if e.get("type") in ("network", "network_connection")]
        }

    except Exception as e:
        print(f"[-] DB fetch error: {e}")
        return None
