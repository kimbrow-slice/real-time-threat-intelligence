import React, { useState } from "react";
import { scanIpAddress } from "./api"; // Import VirusTotal function

function Dashboard() {
  const [ipAddress, setIpAddress] = useState(""); //  State for IP input
  const [result, setResult] = useState(null); //  State to store API response
  const [error, setError] = useState(""); // State for errors

  // Example data for asset inventory, threat-vulnerability mappings, and risk scores
  const [threatData, setThreatData] = useState([
    { name: "SQL Injection", vulnerability: "Web Application", risk_score: 7.5 },
    { name: "Cross-Site Scripting", vulnerability: "Web Application", risk_score: 8.0 },
    { name: "Phishing Attack", vulnerability: "Email", risk_score: 6.0 }
  ]);
  
  // Function to scan IP with VirusTotal
  const fetchIpDetails = async () => {
    if (!ipAddress.trim()) {
      setError("Please enter a valid IP address.");
      return;
    }

    setError(""); // Clear previous errors

    try {
      const data = await scanIpAddress(ipAddress); // Send request to VirusTotal
      setResult(data); // Store API response in state
    } catch (err) {
      setError("Failed to fetch IP details. Ensure the API is reachable.");
      console.error("VirusTotal API request error:", err);
    }
  };

  // Function to render the threat data in a table
  const renderThreats = () => {
    return threatData.map((threat, index) => (
      <tr key={index}>
        <td>{threat.name}</td>
        <td>{threat.vulnerability}</td>
        <td>{threat.risk_score}</td>
      </tr>
    ));
  };

  // Main content for Dashboard
  return (
    <div className="dashboard-container">
      <h1>Threat Intelligence Dashboard</h1>
      <p>Enter an IP address to check for threat intelligence data via VirusTotal.</p>

      {/* Input field for IP address */}
      <input
        type="text"
        placeholder="Enter IP address"
        value={ipAddress}
        onChange={(e) => setIpAddress(e.target.value)}
      />

      {/* Button to trigger API request */}
      <button onClick={fetchIpDetails}>Check IP</button>

      {/* Display API results */}
      {error && <p style={{ color: "red" }}>{error}</p>}

      {result && (
        <div className="result-container">
          <h2>VirusTotal IP Details:</h2>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}

      {/* Display threat-vulnerability mappings and risk scores */}
      <div className="threat-intelligence">
        <h2>Threat Intelligence Overview</h2>
        <table>
          <thead>
            <tr>
              <th>Threat</th>
              <th>Vulnerability</th>
              <th>Risk Score</th>
            </tr>
          </thead>
          <tbody>{renderThreats()}</tbody>
        </table>
      </div>
    </div>
  );
}

export default Dashboard;
