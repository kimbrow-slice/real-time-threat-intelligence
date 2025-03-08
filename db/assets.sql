/*  SUMMARY OF TABLE STRUCTURE


   PARENT TABLE: assets
   - id            --> primary key for table, auto-increment integer.
   - name          --> column size to 255, contains variable characters.
   - category      --> column size to 50, used to identify assets based on its relation to the business.
   - description   --> provides a summary of the asset.

   CHILD TABLES: hardware, software, data, people, processes
   - hardware:
       - hardware_type   --> Type of hardware (e.g., Server, Firewall).
       - manufacturer    --> Manufacturer of the hardware.
       - model           --> Model name or number.
   - software:
       - software_version --> Version number of the software.
       - vendor           --> Software provider/vendor.
   - data:
       - data_classification --> Classification level (Confidential, Internal, External).
   - people:
       - role           --> Defines role type (Employee, IT Staff, Customer).
   - processes:
       - process_type   --> Type of process (e.g., Payment Processing).
       - frequency      --> Process frequency (e.g., Daily, Weekly).
*/


/*  Asset Inventory Database Schema */
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL CHECK (category IN ('Hardware', 'Software', 'Data', 'People', 'Process')),
    description TEXT
);

/*  Hardware Table */
CREATE TABLE hardware (
    id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    hardware_type VARCHAR(255) NOT NULL,
    manufacturer VARCHAR(255),
    model VARCHAR(255)
) INHERITS (assets);

/*  Hardware Table insert placeholder 
INSERT INTO assets (name, category, description) VALUES ('Firewall Appliance', 'Hardware', 'Cisco ASA firewall for network security'); INSERT INTO hardware (id, hardware_type, manufacturer, model) VALUES (LASTVAL(), 'Firewall', 'Cisco', 'ASA 5508-X'); */

/*  Software Table */
CREATE TABLE software (
    id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    software_version VARCHAR(50) NOT NULL,
    vendor VARCHAR(255)
) INHERITS (assets);

/*  Software Table insert placeholder
INSERT INTO assets (name, category, description) VALUES ('Customer Management System', 'Software', 'Handles customer interactions and support.'); INSERT INTO software (id, software_version, vendor) VALUES (LASTVAL(), 'v3.2.1', 'Salesforce'); */

/*  Data Table */
CREATE TABLE data (
    id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    data_classification VARCHAR(12) CHECK (data_classification IN ('Confidential', 'Internal', 'External'))
) INHERITS (assets);

/*  Data Table insert placeholder
INSERT INTO assets (name, category, description) VALUES ('Customer Payment Records', 'Data', 'Sensitive financial transaction logs.'); INSERT INTO data (id, data_classification) VALUES (LASTVAL(), 'Confidential'); */

/*  People Table */
CREATE TABLE people (
    id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    role VARCHAR(255) NOT NULL -- Defines if it's an employee, IT staff, or customer
) INHERITS (assets);

/*  People Table insert placeholder 
INSERT INTO assets (name, category, description) VALUES ('John Doe - IT Security Engineer', 'People', 'Responsible for monitoring security events.'); INSERT INTO people (id, role) VALUES (LASTVAL(), 'IT Staff'); */

/*  Process Table */
CREATE TABLE processes (
    id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    process_type VARCHAR(255) NOT NULL,
    frequency VARCHAR(50) -- Example: "Daily", "Weekly", etc.
) INHERITS (assets);

/* Process Table insert placeholder
INSERT INTO assets (name, category, description) VALUES ('Database Backup Process', 'Process', 'Automated daily database backups.'); INSERT INTO processes (id, process_type, frequency) VALUES (LASTVAL(), 'Backup', 'Daily'); */



/* Example Queries for asset management

-- Retrieve all assets
SELECT * FROM assets;

-- Retrieve all hardware assets
SELECT * FROM hardware;

-- Retrieve all software assets
SELECT * FROM software;

-- Retrieve all classified data
SELECT * FROM data WHERE data_classification = 'Confidential';

-- Retrieve all employees in the "People" category
SELECT * FROM people WHERE role = 'Employee';

-- Retrieve all processes that occur daily
SELECT * FROM processes WHERE frequency = 'Daily';

-- Retrieve a detailed view of all assets, joining specific details
SELECT a.id, a.name, a.category, a.description, 
       h.hardware_type, h.manufacturer, h.model
FROM assets a
LEFT JOIN hardware h ON a.id = h.id
WHERE a.category = 'Hardware';
*/
