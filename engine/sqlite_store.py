"""
PhantomDroid — SQLite Storage Engine
Handles local storage of threat events, scan sessions, and ad correlations.
Ensures private, local-first data retention with minimal storage footprint.
"""

import os
import sqlite3
import json
from datetime import datetime, timedelta

class SQLiteStore:
    def __init__(self):
        # Create data directory relative to project root
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_dir = os.path.join(self.base_dir, "data")
        os.makedirs(self.data_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "events.db")
        self.init_db()

    def get_connection(self):
        """Returns a connection to the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn

    def init_db(self):
        """Initialize database schemas and create tables if they do not exist."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # 1. Sessions table (tracks background monitor and scan sessions)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                start_time TEXT,
                end_time TEXT,
                mode TEXT,
                total_events INTEGER DEFAULT 0,
                device_id TEXT,
                status TEXT,
                ai_briefing TEXT
            )
        """)
        
        # 2. Events table (tracks raw logs and context metrics)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp TEXT,
                app TEXT,
                permission_type TEXT,
                severity TEXT,
                description TEXT,
                context_json TEXT,
                threat_score INTEGER DEFAULT 0,
                combo_triggered TEXT,
                ad_correlation_json TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """)
        
        # 3. Ad Correlations table (tracks correlated network accesses)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ad_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                app TEXT,
                mic_time TEXT,
                ad_server TEXT,
                seconds_gap REAL,
                probability TEXT,
                timestamp TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """)

        # Add indexes to optimize search and reduce retrieval space complexity
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_correlations_session ON ad_correlations(session_id)")
        
        conn.commit()
        cursor.close()
        conn.close()

    def save_event(self, event_dict):
        """Saves a single threat event to the database."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Extract fields
        session_id = event_dict.get("session_id")
        timestamp = event_dict.get("timestamp") or datetime.now().isoformat()
        app = event_dict.get("app", "unknown")
        
        # Convert permissions involved list to comma separated string or extract it
        perms = event_dict.get("permissions_involved")
        if isinstance(perms, list):
            permission_type = ", ".join(perms)
        else:
            permission_type = str(perms or "")
            
        severity = event_dict.get("severity", "LOW")
        description = event_dict.get("description", "")
        
        context_json = event_dict.get("context_json")
        if not context_json:
            context_json = json.dumps(event_dict.get("context", {}))
            
        threat_score = event_dict.get("threat_score", 0)
        combo_triggered = event_dict.get("combo_triggered")
        
        ad_correlation_json = event_dict.get("ad_correlation_json")
        if not ad_correlation_json:
            ad_correlation_json = json.dumps(event_dict.get("ad_correlation", {}))

        cursor.execute("""
            INSERT INTO events (
                session_id, timestamp, app, permission_type, severity, 
                description, context_json, threat_score, combo_triggered, ad_correlation_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id, timestamp, app, permission_type, severity,
            description, context_json, threat_score, combo_triggered, ad_correlation_json
        ))
        
        # Increment total events counter in session
        if session_id:
            cursor.execute("""
                UPDATE sessions 
                SET total_events = total_events + 1 
                WHERE id = ?
            """, (session_id,))
            
        conn.commit()
        cursor.close()
        conn.close()

    def save_session(self, session_dict):
        """Saves or updates a scan session in the database."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        session_id = session_dict.get("id") or session_dict.get("session_id")
        start_time = session_dict.get("start_time")
        end_time = session_dict.get("end_time")
        mode = session_dict.get("mode")
        total_events = session_dict.get("total_events", 0)
        device_id = session_dict.get("device_id")
        status = session_dict.get("status", "active")
        ai_briefing = session_dict.get("ai_briefing")

        # Check if session exists to update
        cursor.execute("SELECT id FROM sessions WHERE id = ?", (session_id,))
        row = cursor.fetchone()
        
        if row:
            # Build dynamic UPDATE query based on values provided
            updates = []
            params = []
            if end_time:
                updates.append("end_time = ?")
                params.append(end_time)
            if status:
                updates.append("status = ?")
                params.append(status)
            if total_events:
                updates.append("total_events = ?")
                params.append(total_events)
            if ai_briefing:
                updates.append("ai_briefing = ?")
                params.append(ai_briefing)
                
            if updates:
                params.append(session_id)
                query = f"UPDATE sessions SET {', '.join(updates)} WHERE id = ?"
                cursor.execute(query, tuple(params))
        else:
            if not start_time:
                start_time = datetime.now().isoformat()
            cursor.execute("""
                INSERT INTO sessions (id, start_time, end_time, mode, total_events, device_id, status, ai_briefing)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (session_id, start_time, end_time, mode, total_events, device_id, status, ai_briefing))

        conn.commit()
        cursor.close()
        conn.close()

    def save_ad_correlation(self, corr_dict):
        """Saves an ad correlation event."""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO ad_correlations (
                session_id, app, mic_time, ad_server, seconds_gap, probability, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            corr_dict.get("session_id"),
            corr_dict.get("app"),
            corr_dict.get("mic_time"),
            corr_dict.get("ad_server"),
            corr_dict.get("seconds_gap"),
            corr_dict.get("probability"),
            corr_dict.get("timestamp") or datetime.now().isoformat()
        ))

        conn.commit()
        cursor.close()
        conn.close()

    def get_events_last_24h(self) -> list:
        """Fetches all events logged in the last 24 hours."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        limit_time = (datetime.now() - timedelta(hours=24)).isoformat()
        cursor.execute("""
            SELECT * FROM events 
            WHERE timestamp >= ? 
            ORDER BY timestamp DESC
        """, (limit_time,))
        
        rows = cursor.fetchall()
        events = [dict(r) for r in rows]
        
        # Deserialize JSON strings for cleaner dictionary handling
        for ev in events:
            if ev.get("context_json"):
                try:
                    ev["context"] = json.loads(ev["context_json"])
                except Exception:
                    ev["context"] = {}
            if ev.get("ad_correlation_json"):
                try:
                    ev["ad_correlation"] = json.loads(ev["ad_correlation_json"])
                except Exception:
                    ev["ad_correlation"] = {}
                    
        cursor.close()
        conn.close()
        return events

    def get_ad_correlations_by_session(self, session_id) -> list:
        """Returns all ad correlations associated with a specific session ID."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM ad_correlations 
            WHERE session_id = ? 
            ORDER BY timestamp DESC
        """, (session_id,))
        
        rows = cursor.fetchall()
        correlations = [dict(r) for r in rows]
        
        cursor.close()
        conn.close()
        return correlations

    def get_daily_summary(self) -> dict:
        """
        Generates a summary of events aggregated by application and permission type
        for the last 24 hours.
        Returns: { app: { permission: count, ... }, ... }
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        limit_time = (datetime.now() - timedelta(hours=24)).isoformat()
        cursor.execute("""
            SELECT app, permission_type, COUNT(*) as count 
            FROM events 
            WHERE timestamp >= ? AND permission_type != ''
            GROUP BY app, permission_type
        """, (limit_time,))
        
        rows = cursor.fetchall()
        summary = {}
        for r in rows:
            app = r["app"]
            perm = r["permission_type"]
            count = r["count"]
            
            if app not in summary:
                summary[app] = {}
            
            # Since permission_type might contain comma separated lists, split them
            for p in [p.strip() for p in perm.split(",")]:
                if p:
                    summary[app][p] = summary[app].get(p, 0) + count
                    
        cursor.close()
        conn.close()
        return summary
