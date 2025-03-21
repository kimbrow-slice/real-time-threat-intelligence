import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { scanIpAddress, shodanScanIp } from "./api";

function Dashboard() {
  const navigate = useNavigate();

  const [vtIpAddress, setVtIpAddress] = useState("");
  const [shodanIpAddress, setShodanIpAddress] = useState("");
  const [vtResult, setVtResult] = useState(null);
  const [shodanResult, setShodanResult] = useState(null);
  const [error, setError] = useState("");
  const [userId, setUserId] = useState(null);

  const [threatData] = useState([
    { name: "SQL Injection", vulnerability: "Web Application", risk_score: 7.5 },
    { name: "Cross-Site Scripting", vulnerability: "Web Application", risk_score: 8.0 },
    { name: "Phishing Attack", vulnerability: "Email", risk_score: 6.0 }
  ]);

  useEffect(() => {
    const storedUserId = localStorage.getItem("user_id");
    if (!storedUserId) {
      navigate("/"); // Redirect if no session
    } else {
      setUserId(storedUserId);
    }
  }, [navigate]);

  const handleLogout = () => {
    localStorage.removeItem("user_id");
    navigate("/");
  };

  const fetchVirusTotalDetails = async () => {
    if (!vtIpAddress.trim()) {
      setError("Please enter a valid IP address for VirusTotal.");
      return;
    }

    setError("");

    try {
      const vtData = await scanIpAddress(vtIpAddress, userId); // 👈 Pass user ID
      setVtResult(vtData);
    } catch (err) {
      setError("Failed to fetch VirusTotal details.");
      console.error("VirusTotal API request error:", err);
    }
  };

  const fetchShodanDetails = async () => {
    if (!shodanIpAddress.trim()) {
      setError("Please enter a valid IP address for Shodan.");
      return;
    }

    setError("");

    try {
      const shodanData = await shodanScanIp(shodanIpAddress);
      setShodanResult(shodanData);
    } catch (err) {
      setError("Failed to fetch Shodan details.");
      console.error("Shodan API request error:", err);
    }
  };

  const renderThreats = () => {
    return threatData.map((threat, index) => (
      <tr key={index}>
        <td>{threat.name}</td>
        <td>{threat.vulnerability}</td>
        <td>{threat.risk_score}</td>
      </tr>
    ));
  };

  const renderVirusTotalCard = () => {
    if (!vtResult) return null;

    const { attributes } = vtResult.data;

    return (
      <div className="card">
        <h3>VirusTotal Data</h3>
        <ul>
          <li><strong>Owner:</strong> {attributes.as_owner} (AS{attributes.asn})</li>
          <li><strong>Location:</strong> {attributes.country} ({attributes.continent})</li>
          <li><strong>Network:</strong> {attributes.network}</li>
          <li><strong>Reputation:</strong> {attributes.reputation}</li>
          <li><strong>Harmless Engines:</strong> {attributes.last_analysis_stats.harmless}</li>
          <li><strong>Malicious Engines:</strong> {attributes.last_analysis_stats.malicious}</li>
          <li><strong>Suspicious Engines:</strong> {attributes.last_analysis_stats.suspicious}</li>
        </ul>
        <a href={vtResult.data.links.self} target="_blank" rel="noopener noreferrer">Full VT Report</a>
      </div>
    );
  };

  const renderShodanCard = () => {
    if (!shodanResult) return null;

    return (
      <div className="card">
        <h3>Shodan Data</h3>
        <ul>
          <li><strong>Organization:</strong> {shodanResult.org}</li>
          <li><strong>Operating System:</strong> {shodanResult.os || "N/A"}</li>
          <li><strong>ISP:</strong> {shodanResult.isp}</li>
          <li><strong>Open Ports:</strong> {shodanResult.ports.join(", ")}</li>
          <li><strong>Hostnames:</strong> {shodanResult.hostnames.join(", ") || "None"}</li>
        </ul>
        <a href={`https://www.shodan.io/host/${shodanIpAddress}`} target="_blank" rel="noopener noreferrer">Full Shodan Report</a>
      </div>
    );
  };

  return (
    <div className="dashboard-container">
      <div className="header">
        <h1>Threat Intelligence Dashboard</h1>
        <button onClick={handleLogout} style={{ float: "right" }}>
          Logout
        </button>
      </div>

      <div className="input-section">
        <h2>VirusTotal Lookup</h2>
        <input
          type="text"
          placeholder="Enter IP address for VirusTotal"
          value={vtIpAddress}
          onChange={(e) => setVtIpAddress(e.target.value)}
        />
        <button onClick={fetchVirusTotalDetails}>Check VirusTotal</button>
      </div>

      <div className="input-section">
        <h2>Shodan Lookup</h2>
        <input
          type="text"
          placeholder="Enter IP address for Shodan"
          value={shodanIpAddress}
          onChange={(e) => setShodanIpAddress(e.target.value)}
        />
        <button onClick={fetchShodanDetails}>Check Shodan</button>
      </div>

      {error && <p style={{ color: "red" }}>{error}</p>}

      <div className="results-container">
        {renderVirusTotalCard()}
        {renderShodanCard()}
      </div>

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
