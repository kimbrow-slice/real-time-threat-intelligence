-- Assets Table
CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(50),
    description TEXT
);

-- Threats Table
CREATE TABLE IF NOT EXISTS threats (
    id SERIAL PRIMARY KEY,
    asset_id INT REFERENCES assets(id) ON DELETE CASCADE,
    threat_name VARCHAR(255) NOT NULL,
    risk_level INT CHECK (risk_level BETWEEN 1 AND 10)
);

-- Vulnerabilities Table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    asset_id INT REFERENCES assets(id) ON DELETE CASCADE,
    vulnerability_name VARCHAR(255) NOT NULL,
    severity_level INT CHECK (severity_level BETWEEN 1 AND 10)
);

-- Risk Rating Table
CREATE TABLE IF NOT EXISTS risk_ratings (
    id SERIAL PRIMARY KEY,
    asset_id INT REFERENCES assets(id) ON DELETE CASCADE,
    threat_id INT REFERENCES threats(id) ON DELETE CASCADE,
    vulnerability_id INT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    risk_score INT CHECK (risk_score BETWEEN 1 AND 100),
    risk_description TEXT
);

-- Users Table
CREATE TABLE IF NOT EXISTS public.users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- IP Scans Table
CREATE TABLE IF NOT EXISTS public.ip_scans (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    scan_data JSONB, 
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create the alerts table if it doesn't already exist
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    threat_name VARCHAR(255) NOT NULL,
    risk_score INT NOT NULL,
    alert_type VARCHAR(50) NOT NULL,
    alert_description TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create the logs table if it doesn't already exist
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- Create the threat_data table if it doesn't already exist
CREATE TABLE IF NOT EXISTS threat_data (
    id SERIAL PRIMARY KEY,
    threat_type VARCHAR(255) NOT NULL,
    risk_score INT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data in alert table
INSERT INTO threat_data (threat_type, risk_score, description)
VALUES
    ('SQL Injection', 25, 'Injection vulnerability in SQL queries'),
    ('Phishing Attack', 30, 'Credential theft through phishing email'),
    ('Data Breach', 35, 'Unauthorized access leading to data exposure');
