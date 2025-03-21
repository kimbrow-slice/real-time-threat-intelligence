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

CREATE TABLE logs (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    action_type VARCHAR(100) NOT NULL,         -- e.g., 'login', 'scan_ip', 'get_shodan_data'
    details TEXT,                              -- e.g., scanned IP or endpoint info
    timestamp TIMESTAMPTZ DEFAULT NOW()
);
