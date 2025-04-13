-- TVA Mapping table linking assets, threats, and vulnerabilities
CREATE TABLE tva_mapping (
    id SERIAL PRIMARY KEY, -- Unique identifier for each record
    asset_id INT REFERENCES assets(id), -- Key referencing assets table
    threat_name VARCHAR(255) NOT NULL, -- Name of the identified threat
    vulnerability_description TEXT NOT NULL, -- Description of the associated vulnerability
    likelihood INT CHECK (likelihood BETWEEN 1 AND 5) NOT NULL, -- Likelihood of exploitation (1-5 = Low-High)
    impact INT CHECK (impact BETWEEN 1 AND 5) NOT NULL, -- Potential impact of exploitation (1-5 = Low-High)
    risk_score INT GENERATED ALWAYS AS (likelihood * impact) STORED -- Computed risk score
);

-- Creating assets with id 1 through 5 for asset tables
INSERT INTO assets (id, name, category, description) VALUES
(1, 'Firewall Appliance', 'Hardware', 'Cisco ASA firewall.'),
(2, 'Customer Management System', 'Software', 'Salesforce-based.'),
(3, 'Payment Records', 'Data', 'Sensitive card data.'),
(4, 'John Doe - Engineer', 'People', 'IT Security Engineer.'),
(5, 'Backup Process', 'Process', 'Daily DB backups.');


-- Initial dataset with threat-vulnerability pairs
INSERT INTO tva_mapping (asset_id, threat_name, vulnerability_description, likelihood, impact)
VALUES
    (1, 'Unauthorized Access', 'Misconfigured firewall rules exposing internal systems.', 4, 5),
    (2, 'SQL Injection', 'Web forms accepting unvalidated user input.', 5, 4), 
    (3, 'Data Breach', 'Weak encryption on stored payment records.', 4, 5),
    (4, 'Phishing Attack', 'Lack of awareness training leading to credential theft.', 4, 5), 
    (5, 'Malicious File Execution', 'OSINT Tool flagged malware in backup files.', 4, 5); 


-- updating tva analysis
UPDATE tva_mapping
SET likelihood = 5 /* <-- hardcoded likelihood?  */
WHERE threat_name = 'Unauthorized Access'
AND EXISTS (SELECT 1 FROM threat_data WHERE threat_data.threat_type =
'Unauthorized Access' AND threat_data.risk_score > 20); /* <-- hardcoded risk score? */ 

UPDATE tva_mapping
SET likelihood = 5 /* <-- hardcoded likelihood?  */
WHERE threat_name = 'SQL Injection'
AND EXISTS (SELECT 1 FROM threat_data WHERE threat_data.threat_type =
'SQL Injection' AND threat_data.risk_score > 20); /* <-- hardcoded risk score? */ 

UPDATE tva_mapping
SET likelihood = 5 /* <-- hardcoded likelihood?  */
WHERE threat_name = 'Data Breach'
AND EXISTS (SELECT 1 FROM threat_data WHERE threat_data.threat_type =
'Data Breach' AND threat_data.risk_score > 20); /* <-- hardcoded risk score? */ 

UPDATE tva_mapping
SET likelihood = 5 /* <-- hardcoded likelihood?  */
WHERE threat_name = 'Phishing Attack'
AND EXISTS (SELECT 1 FROM threat_data WHERE threat_data.threat_type =
'Phishing Attack' AND threat_data.risk_score > 20); /* <-- hardcoded risk score? */ 

UPDATE tva_mapping
SET likelihood = 5 /* <-- hardcoded likelihood?  */
WHERE threat_name = 'Malicious File Execution'
AND EXISTS (SELECT 1 FROM threat_data WHERE threat_data.threat_type =
'Malicious File Execution' AND threat_data.risk_score > 20); /* <-- hardcoded risk score? */ 
