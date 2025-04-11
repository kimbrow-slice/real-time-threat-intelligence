-- Indexes for performance optimization

-- Index to speed up JOINs and filters on asset_id in threats table
CREATE INDEX idx_threat_asset_id ON threats(asset_id);

-- Index to speed up searches by threat name
CREATE INDEX idx_threat_name ON threats(threat_name);

-- Index to optimize JOINs and filters on asset_id in vulnerabilities table
CREATE INDEX idx_vuln_asset_id ON vulnerabilities(asset_id);

-- Index to speed up searches by vulnerability name
CREATE INDEX idx_vuln_name ON vulnerabilities(vulnerability_name);

-- Indexes to improve performance of JOINs and WHERE clauses in risk_ratings
CREATE INDEX idx_rating_asset_id ON risk_ratings(asset_id);
CREATE INDEX idx_rating_threat_id ON risk_ratings(threat_id);
CREATE INDEX idx_rating_vuln_id ON risk_ratings(vulnerability_id);

-- Asset Threat & Vulnerability Overview
-- Returns each asset with its threat name, vulnerability name, and risk score
-- Uses LEFT JOINs to include assets even if no threats or vulnerabilities are recorded
SELECT 
    a.name AS asset_name,
    t.threat_name,
    v.vulnerability_name,
    rr.risk_score
FROM 
    assets a
LEFT JOIN threats t ON a.id = t.asset_id
LEFT JOIN vulnerabilities v ON a.id = v.asset_id
LEFT JOIN risk_ratings rr ON a.id = rr.asset_id
ORDER BY rr.risk_score DESC;


-- Risk Summary per Asset
-- Shows each asset’s average and maximum risk score
-- Useful for dashboards or reports that track risk exposure
SELECT 
    a.name AS asset_name,
    MAX(rr.risk_score) AS max_risk,
    AVG(rr.risk_score) AS avg_risk
FROM 
    assets a
JOIN risk_ratings rr ON a.id = rr.asset_id
GROUP BY a.name
ORDER BY avg_risk DESC;

-- Backup & Restore Command Example
-- Backup Command Example
-- pg_dump -U username -d your_database -F c -f backup_file.bak

-- Restore Command Example
-- pg_restore -U username -d your_database -c backup_file.bak


