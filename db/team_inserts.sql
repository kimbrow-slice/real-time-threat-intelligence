INSERT INTO assets (name, category, description)
VALUES ('Madison Alexander', 'People', 'Oversees project scope, schedule, and resources. Coordinates team communication, sets deadlines, manages risk, and ensures deliverables meet requirements.');
INSERT INTO people (id, role)
VALUES (LASTVAL(), 'Project Manager');

INSERT INTO assets (name, category, description)
VALUES ('Kenneth Kakie', 'People', 'Conducts open-source intelligence gathering to identify threats and vulnerabilities. Researches publicly available data, analyzes risks, and provides actionable security insights.');
INSERT INTO people (id, role)
VALUES (LASTVAL(), 'OSINT Specialist');

INSERT INTO assets (name, category, description)
VALUES ('Hashim Abdulla', 'People', 'Evaluates potential threats and their business impact. Develops mitigation strategies, monitors risk levels, and advises on security priorities based on likelihood and impact.');
INSERT INTO people (id, role)
VALUES (LASTVAL(), 'Risk Analyst');

INSERT INTO assets (name, category, description)
VALUES ('Jeffery Kimbrow', 'People', 'Drives core software development, from design to deployment. Manages code quality, implements features, and oversees technical architecture to ensure a robust solution.');
INSERT INTO people (id, role)
VALUES (LASTVAL(), 'Main Developer');

INSERT INTO assets (name, category, description)
VALUES ('Mohamed Elgasim', 'People', 'Maintains repository structure, manages branching and merging strategies, and enforces version control best practices. Monitors commits, pull requests, and code integrity.');
INSERT INTO people (id, role)
VALUES (LASTVAL(), 'Git Admin');