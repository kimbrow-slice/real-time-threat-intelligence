-- incident_response.sql

CREATE TABLE incident_response (
  id SERIAL PRIMARY KEY,
  incident VARCHAR(255) NOT NULL,
  date DATE NOT NULL,
  response_plan TEXT NOT NULL
);

CREATE TABLE incident_logs (
  id SERIAL PRIMARY KEY,
  incident_response_id INTEGER NOT NULL REFERENCES incident_response(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
