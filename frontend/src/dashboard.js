import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  scanIpAddress,
  shodanScanIp,
  scanDependencies,
  getEPSSData,
  enrichRisks,
  fetchShodanSearchData,
  fetchShodanDnsResolveData,
} from "./api";

const samplePackages = [
  { name: "axios", version: "1.8.1", ecosystem: "npm", source: "npm-audit" },
  { name: "jinja2", version: "3.1.5", ecosystem: "PyPI", source: "pip-audit" },
  { name: "flask", version: "3.1.0", ecosystem: "PyPI", source: "pip-audit" },
  { name: "requests", version: "2.32.3", ecosystem: "PyPI", source: "pip-audit" },
];

function Dashboard() {
  const navigate = useNavigate();
  const [vtIpAddress, setVtIpAddress] = useState("");
  const [shodanIpAddress, setShodanIpAddress] = useState("");
  const [shodanQuery, setShodanQuery] = useState("");
  const [shodanHostnames, setShodanHostnames] = useState("");
  const [vtResult, setVtResult] = useState(null);
  const [shodanResult, setShodanResult] = useState(null);
  const [shodanSearchResult, setShodanSearchResult] = useState(null);
  const [shodanDnsResult, setShodanDnsResult] = useState(null);
  const [epssData, setEpssData] = useState([]);
  const [error, setError] = useState("");
  const [userId, setUserId] = useState(null);
  const [loading, setLoading] = useState(true);

  const [isVtCardOpen, setIsVtCardOpen] = useState(false);
  const [isShodanCardOpen, setIsShodanCardOpen] = useState(false);
  const [isShodanSearchCardOpen, setIsShodanSearchCardOpen] = useState(false);
  const [isShodanDnsResolveCardOpen, setIsShodanDnsResolveCardOpen] = useState(false);

  useEffect(() => {
    const storedUserId = localStorage.getItem("user_id");
    if (!storedUserId) navigate("/");
    else setUserId(storedUserId);
  }, [navigate]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const osvResponse = await scanDependencies(samplePackages);
        const normalizedOSV = Array.isArray(osvResponse)
          ? osvResponse
          : osvResponse.results || [];

        const advisoriesWithCVEs = normalizedOSV.flatMap((entry) =>
          (entry.aliases || [])
            .filter((alias) => alias.startsWith("CVE-"))
            .map((cve) => ({
              cve,
              package: entry.package,
              version: entry.version,
              original_id: entry.osv_id,
              summary: entry.summary
            }))
        );

        const epssResponse = await getEPSSData(advisoriesWithCVEs);
        const enriched = await enrichRisks(epssResponse);
        setEpssData(enriched); // Ensure data is an array
      } catch (err) {
        console.error("Failed to fetch vulnerability data:", err);
      }
    };

    fetchData();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("user_id");
    navigate("/");
  };

  const fetchVirusTotalDetails = async () => {
    if (!vtIpAddress.trim()) {
      setError("Please enter a valid IP address for VirusTotal.");
      return;
    }

    try {
      const vtData = await scanIpAddress(vtIpAddress, userId);
      setVtResult(vtData);
      setError("");
    } catch {
      setError("Failed to fetch VirusTotal details.");
    }
  };

  const fetchShodanDetails = async () => {
    if (!shodanIpAddress.trim()) {
      setError("Please enter a valid IP address for Shodan.");
      return;
    }

    try {
      const shodanData = await shodanScanIp(shodanIpAddress);
      setShodanResult(shodanData);
      setError("");
    } catch {
      setError("Failed to fetch Shodan details.");
    }
  };

  const fetchShodanSearch = async () => {
    if (!shodanQuery.trim()) {
      setError("Please enter a search query for Shodan.");
      return;
    }

    try {
      const searchResult = await fetchShodanSearchData(shodanQuery);
      setShodanSearchResult(searchResult);
      setError("");
    } catch {
      setError("Failed to fetch Shodan search results.");
    }
  };

  const fetchShodanDnsResolve = async () => {
    if (!shodanHostnames.trim()) {
      setError("Please enter hostnames to resolve via Shodan.");
      return;
    }

    try {
      const dnsResult = await fetchShodanDnsResolveData(shodanHostnames);
      setShodanDnsResult(dnsResult);
      setError("");
    } catch {
      setError("Failed to fetch Shodan DNS resolve results.");
    }
  };

  const toggleVtCard = () => setIsVtCardOpen(!isVtCardOpen);
  const toggleShodanCard = () => setIsShodanCardOpen(!isShodanCardOpen);
  const toggleShodanSearchCard = () => setIsShodanSearchCardOpen(!isShodanSearchCardOpen);
  const toggleShodanDnsResolveCard = () => setIsShodanDnsResolveCardOpen(!isShodanDnsResolveCardOpen);

  const renderVirusTotalCard = () => {
    if (!vtResult) return null;
    const { attributes } = vtResult.data;

    return (
      <div className="card siem-card">
        <h2 onClick={toggleVtCard} style={{ cursor: "pointer" }}>
          {isVtCardOpen ? "▲ VirusTotal Results" : "▼ VirusTotal Results"}
        </h2>
        {isVtCardOpen && (
          <ul>
            <li><strong>Owner:</strong> {attributes.as_owner} (AS{attributes.asn})</li>
            <li><strong>Location:</strong> {attributes.country} ({attributes.continent})</li>
            <li><strong>Network:</strong> {attributes.network}</li>
            <li><strong>Reputation:</strong> {attributes.reputation}</li>
            <li><strong>Malicious:</strong> {attributes.last_analysis_stats.malicious}</li>
            <li><strong>Suspicious:</strong> {attributes.last_analysis_stats.suspicious}</li>
          </ul>
        )}
        {isVtCardOpen && <a href={vtResult.data.links.self} target="_blank" rel="noopener noreferrer">View Full Report</a>}
      </div>
    );
  };

  const renderShodanCard = () => {
    if (!shodanResult) return null;

    return (
      <div className="card siem-card">
        <h2 onClick={toggleShodanCard} style={{ cursor: "pointer" }}>
          {isShodanCardOpen ? "▲ Shodan IP" : "▼ Shodan IP"}
        </h2>
        {isShodanCardOpen && (
          <ul>
            <li><strong>Organization:</strong> {shodanResult.org}</li>
            <li><strong>OS:</strong> {shodanResult.os || "N/A"}</li>
            <li><strong>ISP:</strong> {shodanResult.isp}</li>
            <li><strong>Open Ports:</strong> {shodanResult.ports.join(", ")}</li>
            <li><strong>Hostnames:</strong> {shodanResult.hostnames.join(", ") || "None"}</li>
          </ul>
        )}
        {isShodanCardOpen && <a href={`https://www.shodan.io/host/${shodanIpAddress}`} target="_blank" rel="noopener noreferrer">View Full Report</a>}
      </div>
    );
  };

  const renderShodanSearchCard = () => {
    if (!shodanSearchResult) return null;

    return (
      <div className="card siem-card">
        <h2 onClick={toggleShodanSearchCard} style={{ cursor: "pointer" }}>
          {isShodanSearchCardOpen ? "▲ Shodan Search Results" : "▼ Shodan Search Results"}
        </h2>
        {isShodanSearchCardOpen && (
          <pre>{JSON.stringify(shodanSearchResult, null, 2)}</pre>
        )}
      </div>
    );
  };

  const renderShodanDnsResolveCard = () => {
    if (!shodanDnsResult) return null;

    return (
      <div className="card siem-card">
        <h2 onClick={toggleShodanDnsResolveCard} style={{ cursor: "pointer" }}>
          {isShodanDnsResolveCardOpen ? "▲ Shodan DNS Resolve Results" : "▼ Shodan DNS Resolve Results"}
        </h2>
        {isShodanDnsResolveCardOpen && (
          <pre>{JSON.stringify(shodanDnsResult, null, 2)}</pre>
        )}
      </div>
    );
  };

  return (
    <div className="dashboard-container">
      <div className="header">
        <h1> Real Time Threat Intelligence Dashboard</h1>
        <button onClick={handleLogout}>Logout</button>
      </div>

      <section className="input-section">
        <h2>API Scans</h2>

        <div className="lookup">
          <label>VirusTotal IP: </label>
          <input
            type="text"
            placeholder="Enter IP"
            value={vtIpAddress}
            onChange={(e) => setVtIpAddress(e.target.value)}
          />
          <button onClick={fetchVirusTotalDetails}>Scan</button>
        </div>

        <div className="lookup">
          <label>Shodan IP: </label>
          <input
            type="text"
            placeholder="Enter IP"
            value={shodanIpAddress}
            onChange={(e) => setShodanIpAddress(e.target.value)}
          />
          <button onClick={fetchShodanDetails}>Scan</button>
        </div>

        <div className="lookup">
          <label>Shodan Query: </label>
          <input
            type="text"
            placeholder="Enter query"
            value={shodanQuery}
            onChange={(e) => setShodanQuery(e.target.value)}
          />
          <button onClick={fetchShodanSearch}>Search</button>
        </div>

        <div className="lookup">
          <label>Shodan Hostnames: </label>
          <input
            type="text"
            placeholder="Enter hostnames"
            value={shodanHostnames}
            onChange={(e) => setShodanHostnames(e.target.value)}
          />
          <button onClick={fetchShodanDnsResolve}>Resolve DNS</button>
        </div>

        {error && <p className="error">{error}</p>}
      </section>

      <section className="results">
        {renderVirusTotalCard()}
        {renderShodanCard()}
        {renderShodanSearchCard()}
        {renderShodanDnsResolveCard()}
      </section>

      <div className="epss-section">
        <h2>Dependency Risk Intelligence</h2>
        {loading ? (
          <p>Loading EPSS data...</p>
        ) : epssData && epssData.length > 0 ? (
          <table className="siem-table">
            <thead>
              <tr>
                <th>Pkg</th>
                <th>Ver</th>
                <th>CVE</th>
                <th>EPSS</th>
                <th>30d Exploit %</th>
                <th>Date</th>
                <th>Summary</th>
                <th>Risk</th>
                <th>Category</th>
              </tr>
            </thead>
            <tbody>
              {epssData.map((entry, index) => {
                const riskColor = {
                  "Critical Risk": "#DC2626", 
                  "High Risk": "#F97316",     
                  "Moderate Risk": "#FACC15", 
                  "Low Risk": "#10B981",      
                  "No Risk": "#6B7280"        
                }[entry.risk_label] || "#D1D5DB";

                return (
                  <tr key={index}>
                    <td>{entry.package}</td>
                    <td>{entry.version}</td>
                    <td>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${entry.cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {entry.cve}
                      </a>
                    </td>
                    <td>{(entry.epss * 100).toFixed(2)}</td>
                    <td>{(entry.percentile * 100).toFixed(2)}%</td>
                    <td>{entry.date}</td>
                    <td title={entry.summary}>
                      {entry.summary.length > 60
                        ? `${entry.summary.slice(0, 60)}...`
                        : entry.summary}
                    </td>
                    <td>{entry.risk_score}</td>
                    <td>
                      <span
                        style={{
                          backgroundColor: riskColor,
                          padding: "4px 8px",
                          borderRadius: "6px",
                          color: "white",
                          fontWeight: "bold",
                          fontSize: "0.85rem"
                        }}
                      >
                        {entry.risk_label}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <p>No CVEs with EPSS scores found.</p>
        )}
      </div>
    </div>
  );
}

export default Dashboard;
