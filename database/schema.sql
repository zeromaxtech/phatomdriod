-- PhantomDroid Database Schema
-- Run this once to set up your MySQL database

CREATE DATABASE IF NOT EXISTS phantomdroid;
USE phantomdroid;

-- Scan sessions table
CREATE TABLE IF NOT EXISTS scan_sessions (
    id VARCHAR(36) PRIMARY KEY,
    device_id VARCHAR(100),
    start_time DATETIME,
    end_time DATETIME,
    status VARCHAR(20) DEFAULT 'active',
    threat_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Live threat events
CREATE TABLE IF NOT EXISTS threat_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(36),
    app VARCHAR(200),
    type VARCHAR(50),         -- behavior | permission_scan | network | network_connection
    severity VARCHAR(20),     -- CRITICAL | HIGH | MEDIUM | LOW
    description TEXT,
    threat_score INT DEFAULT 0,
    raw_data JSON,
    timestamp DATETIME,
    INDEX idx_session (session_id),
    INDEX idx_severity (severity),
    INDEX idx_app (app)
);

-- AI-generated forensic reports
CREATE TABLE IF NOT EXISTS ai_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(36),
    report_json JSON,
    pdf_path VARCHAR(500),
    generated_at DATETIME,
    overall_risk VARCHAR(20)  -- CRITICAL | HIGH | MEDIUM | LOW
);

-- App permission profiles (snapshot per session)
CREATE TABLE IF NOT EXISTS app_profiles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(36),
    app VARCHAR(200),
    permissions JSON,
    risk_score INT DEFAULT 0,
    risk_level VARCHAR(20),
    dangerous_count INT DEFAULT 0,
    scanned_at DATETIME,
    INDEX idx_session (session_id)
);
