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

/*  
   Hardware Table 
   Uses a foreign key to 'assets(id)' instead of INHERITS.
*/
CREATE TABLE hardware (
    id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    hardware_type VARCHAR(255) NOT NULL,
    manufacturer VARCHAR(255),
    model VARCHAR(255)
);


/*  
   Software Table 
   Also references assets(id) 
*/
CREATE TABLE software (
    id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    software_version VARCHAR(50) NOT NULL,
    vendor VARCHAR(255)
);


/*  
   Data Table
*/
CREATE TABLE data (
    id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    data_classification VARCHAR(12) CHECK (data_classification IN ('Confidential', 'Internal', 'External'))
);

/*  
   People Table
*/
CREATE TABLE people (
    id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    role VARCHAR(255) NOT NULL
);

/*  
   Process Table
*/
CREATE TABLE processes (
    id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    process_type VARCHAR(255) NOT NULL,
    frequency VARCHAR(50)  -- Example: "Daily", "Weekly", etc.
);

/* 
   Example Queries for asset management:

   -- Retrieve all assets:
   SELECT * FROM assets;

   -- Retrieve all hardware assets (two-step design):
   SELECT a.id, a.name, a.category, a.description,
          h.hardware_type, h.manufacturer, h.model
     FROM assets a
     LEFT JOIN hardware h ON a.id = h.id
    WHERE a.category = 'Hardware';

   -- Similar approach for software, data, people, processes
*/
