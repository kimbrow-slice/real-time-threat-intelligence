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
  { name: "chart.js", version: "4.4.8", ecosystem: "npm", source: "npm-audit" },
  { name: "jinja2", version: "3.1.5", ecosystem: "PyPI", source: "pip-audit" },
  { name: "flask", version: "3.1.0", ecosystem: "PyPI", source: "pip-audit" },
  { name: "requests", version: "2.32.3", ecosystem: "PyPI", source: "pip-audit" }
  ,
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
  const [loading, setLoading] = useState(false); 
  const [buttonDisabled, setButtonDisabled] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [isVtCardOpen, setIsVtCardOpen] = useState(false);
  const [isShodanCardOpen, setIsShodanCardOpen] = useState(false);
  const [isShodanSearchCardOpen, setIsShodanSearchCardOpen] = useState(false);
  const [isShodanDnsResolveCardOpen, setIsShodanDnsResolveCardOpen] = useState(false);
  const [filteredAlerts, setFilteredAlerts] = useState([]);
  const [alertTypeFilter, setAlertTypeFilter] = useState("");
  const [threatNameFilter, setThreatNameFilter] = useState("");
  const [isAlertOpen, setIsAlertOpen] = useState({});
  const [groupedAlerts, setGroupedAlerts] = useState([]);

  const computeRiskLabel = (score) => {
  if (score >= 4.0) return "Critical Risk";
  else if (score >= 3.0) return "High Risk";
  else if (score >= 2.0) return "Moderate Risk";
  else if (score >= 1.0) return "Low Risk";
  else return "No Risk";
};


// Maps a risk label to its corresponding CSS class.
const getRiskLabelClass = (label) => {
  switch (label) {
    case "Critical Risk":
      return "critical-risk";
    case "High Risk":
      return "high-risk";
    case "Moderate Risk":
      return "moderate-risk";
    case "Low Risk":
      return "low-risk";
    case "No Risk":
      return "no-risk";
    default:
      return "alert-risk"; // fallback if the label is "Alert" or unrecognized
  }
};


  useEffect(() => {
    const storedUserId = localStorage.getItem("user_id");
    if (!storedUserId) navigate("/");
    else setUserId(storedUserId);
  }, [navigate]);
  
  useEffect(() => {

    setButtonDisabled(false);
  }, []);

  const handleFetchEPSS = async () => {
    setLoading(true); // Start loading state when button is clicked
    setButtonDisabled(true); // Disable the button to prevent multiple clicks

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
            summary: entry.summary,
          }))
      );

      const epssResponse = await getEPSSData(advisoriesWithCVEs);
      const enriched = await enrichRisks(epssResponse);
      setEpssData(enriched); // Set the fetched and enriched EPSS data
    } catch (err) {
      console.error("Failed to fetch vulnerability data:", err);
      setError("An error occurred while fetching the EPSS data.");
    } finally {
      setLoading(false); // End loading state
      setButtonDisabled(false); // Re-enable the button
    }
  };

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const response = await fetch("http://localhost:5000/get_alerts");
        if (response.ok) {
          const data = await response.json();
          setAlerts(data);  // Store all alerts in state
          groupAlertsByType(data); // Group alerts by threat_name
        } else {
          setError("Failed to fetch alerts");
        }
      } catch (err) {
        setError("Error fetching alerts");
      } finally {
        setLoading(false);
      }
    };
    fetchAlerts();
  }, []);

  const groupAlertsByType = (alertsData) => {
    const grouped = alertsData.reduce((acc, alert) => {
      if (!acc[alert.threat_name]) {
        acc[alert.threat_name] = [];
      }
      acc[alert.threat_name].push(alert);
      return acc;
    }, {});
    setGroupedAlerts(grouped);
  };
  

  const toggleAlertDetails = (id) => {
    setIsAlertOpen((prevState) => ({
      ...prevState,
      [id]: !prevState[id], // Toggle the open/closed state for the clicked alert
    }));
  };

  useEffect(() => {
    const filtered = alerts.filter(alert => {
      const matchesSeverity = alertTypeFilter ? alert.alert_type === alertTypeFilter : true;
      const matchesType = threatNameFilter ? alert.threat_name.includes(threatNameFilter) : true;
      return matchesSeverity && matchesType;
    });
    setFilteredAlerts(filtered);
  }, [alertTypeFilter, threatNameFilter, alerts]);

  const handleFilterChange = (e, filterType) => {
    if (filterType === "severity") {
      setAlertTypeFilter(e.target.value);
    } else if (filterType === "type") {
      setThreatNameFilter(e.target.value);
    }
  };

  const handleAlertClick = (alertId) => {
    // Navigate to the expanded view of the alert (this would be a new route in your app)
    navigate(`/alert/${alertId}`);
  };


  
  const handleLogout = () => {
    localStorage.removeItem("user_id");
    navigate("/");
  };

  const 
  fetchVirusTotalDetails = async () => {
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

  const renderAlertCards = () => {
    // Group alerts by threat name
    const groupedAlerts = {};
    alerts.forEach((alert) => {
      if (!groupedAlerts[alert.threat_name]) {
        groupedAlerts[alert.threat_name] = [];
      }
      groupedAlerts[alert.threat_name].push(alert);
    });
  
    return Object.keys(groupedAlerts).map((threatName) => {
      const alertCount = groupedAlerts[threatName].length;
      const firstAlert = groupedAlerts[threatName][0];
  
      // If the stored alert_type is "Alert", compute its actual label from risk_score.
      const displayLabel =
        firstAlert.alert_type === "Alert"
          ? computeRiskLabel(firstAlert.risk_score)
          : firstAlert.alert_type;
  
      // Use displayLabel for the CSS class.
      const cardClass = getRiskLabelClass(displayLabel);
  
      return (
        <div className={`card alert-card ${cardClass}`} key={threatName}>
          <h2 onClick={() => toggleAlertDetails(threatName)} style={{ cursor: "pointer" }}>
            {isAlertOpen[threatName] ? "▲" : "▼"} {threatName} ({alertCount} Alerts)
          </h2>
          {isAlertOpen[threatName] ? (
            <ul>
              {groupedAlerts[threatName].map((alert) => {
                // For each alert, if its alert_type is "Alert", compute its proper label.
                const labelForAlert =
                  alert.alert_type === "Alert"
                    ? computeRiskLabel(alert.risk_score)
                    : alert.alert_type;
                return (
                  <li key={alert.id}>
                    <strong>Risk Score:</strong> {Number(alert.risk_score).toFixed(2)} <br />
                    <strong>Description:</strong> {alert.alert_description} <br />
                    <strong>Timestamp:</strong> {new Date(alert.created_at).toLocaleString()} <br />
                    <strong>Risk:</strong> {labelForAlert}
                  </li>
                );
              })}
            </ul>
          ) : (
            <div>
              <strong>Risk Score with Decay Factor:</strong> {Number(firstAlert.risk_score).toFixed(2)} <br />
              <strong>Description:</strong> {firstAlert.alert_description} <br />
              <strong>Timestamp:</strong> {new Date(firstAlert.created_at).toLocaleString()}
            </div>
          )}
          <div>
            <br />
            <span className={`siem-label ${cardClass}`}>
              {displayLabel}
            </span>
          </div>
        </div>
      );
    });
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
        <h1> ShopSmart Solutions SIEM</h1>
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

          <label>Shodan Query: </label>
          <input
            type="text"
            placeholder="Enter query"
            value={shodanQuery}
            onChange={(e) => setShodanQuery(e.target.value)}
          />
          <button onClick={fetchShodanSearch}>Search</button>

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

      <section className="filters-section">
      
      </section>

      {loading ? (
        <p>Loading alerts...</p>
      ) : (
        <section className="alerts-section">
          <h2>Recent Alerts  </h2>
          <div className="filters">
          <div>
            <label>Severity            </label>
            <select onChange={(e) => handleFilterChange(e, "severity")} value={alertTypeFilter}>
              <option value="">All</option>
              <option value="High Risk">High Risk</option>
              <option value="Moderate Risk">Moderate Risk</option>
              <option value="Low Risk">Low Risk</option>
              <option value="Critical Risk">Critical Risk</option>
              <option value="No Risk">No Risk</option>
            </select>
            <label>Threat Type            </label>
            <input
              type="text"
              placeholder="Search by threat type"
              value={threatNameFilter}
              onChange={(e) => handleFilterChange(e, "type")}
            />
          </div>
          <div>
            
          </div>
          </div>


          <div className="alerts-grid">
            {renderAlertCards()}
          </div>
          
        </section>
      )} 

      {error && <p className="error">{error}</p>}

      

      <section className="results">
        {renderVirusTotalCard()}
        {renderShodanCard()}
        {renderShodanSearchCard()}
        {renderShodanDnsResolveCard()}
      </section>

<div className="epss-section">
        <h2>Dependency Risk Intelligence</h2>
        <button 
          onClick={handleFetchEPSS} 
          disabled={buttonDisabled || loading}
        >
          {loading ? "Fetching EPSS Data..." : "Fetch EPSS Data"}
        </button>
        
        {loading ? (
          <p>Loading...</p>
        ) : epssData && epssData.length > 0 ? (
          <table className="siem-table">
            <thead>
              <tr>
                <th>Pkg</th>
                <th>Ver</th>
                <th>CVE</th>
                <th>Enriched Risk Score</th>
                <th>30d Exploit %</th>
                <th>Date</th>
                <th>Summary</th>
                <th>Risk</th>
                <th>Criticality</th>
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
                    <td>{(entry.risk_score).toFixed(2)}</td>
                    <td>{(entry.percentile * 100).toFixed(2)}%</td>
                    <td>{entry.date}</td>
                    <td title={entry.summary}>
                      {entry.summary ? (entry.summary.length > 60 ? `${entry.summary.slice(0, 60)}...` : entry.summary) : "No Summary Available"}
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
                          fontSize: "0.85rem",
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
