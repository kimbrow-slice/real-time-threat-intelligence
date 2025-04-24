import axios from 'axios';
import SHA256 from "crypto-js/sha256";


const SHODAN_API_URL = process.env.REACT_APP_SHODAN_API_URL;
const REACT_APP_SHODAN_API_SEARCH_URL = process.env.REACT_APP_SHODAN_API_SEARCH_URL;
const SHODAN_API_RESOLVE_DNS_URL = process.env.REACT_APP_SHODAN_API_RESOLVE_DNS_URL;
const API_BASE_URL = process.env.REACT_APP_API_URL; 


// Helper to get user_id from localStorage
const getUserId = () => localStorage.getItem("user_id");

// Scan IP using VirusTotal API
export const scanIpAddress = async (ipAddress, userId) => {
  const csrfToken = localStorage.getItem("csrf_token");

  const response = await fetch(
    `${process.env.REACT_APP_API_URL}/scan_ip?ip=${encodeURIComponent(ipAddress)}&user_id=${userId}`,
    {
      method: "GET",
      headers: {
        "X-CSRF-Token": csrfToken,
        "Accept": "application/json",
      },
      credentials: "include" 
    }
  );

  if (!response.ok) {
    throw new Error("CSRF validation or API request failed");
  }

  return await response.json();
};

// Scan IP using Shodan API
export const shodanScanIp = async (ipAddress) => {
  try {
    const userId = getUserId();
    const response = await axios.get(
      `${SHODAN_API_URL}?ip=${ipAddress}&user_id=${userId}`
    );
    return response.data;
  } catch (error) {
    console.error("Shodan API error:", error);
    throw error;
  }
};

// Shodan Search API
export const fetchShodanSearchData = async (query) => {
  try {
    const userId = getUserId();
    const response = await axios.post(
      `${API_BASE_URL}/get_shodan_search_data`,
      { query, user_id: userId },
      {
        headers: {
          "Content-Type": "application/json",
        },
        withCredentials: true,
      }
    );
    return response.data.results;  
  } catch (error) {
    console.error("Shodan Search Error:", error);
    throw error;
  }
};




// Shodan DNS Resolve API (resolving DNS for hostnames)
export const fetchShodanDnsResolveData = async (hostnames) => {
  try {
    const response = await axios.get(
      SHODAN_API_RESOLVE_DNS_URL.replace("{hostnames}", hostnames)
    );
    return response.data;
  } catch (error) {
    console.log("SHODAN_API_RESOLVE_DNS_URL:", SHODAN_API_RESOLVE_DNS_URL);
    console.error("Shodan DNS Resolve Error:", error);
    throw error;
  }
};

// Register a new user
export const registerUser = async (username, password) => {
  try {
    const hashedPassword = SHA256(password).toString();

    const response = await axios.post(`${API_BASE_URL}/register`, {
      username,
      password: hashedPassword,
    });

    return response.data;
  } catch (error) {
    console.error("Registration error:", error.response?.data || error.message);
    throw error;
  }
};

// Log in a user
export const loginUser = async (username, password) => {
  try {
    const response = await axios.post(`${API_BASE_URL}/login`, {
      username,
      password,
    });
    return response.data;
  } catch (error) {
    console.error("Login error:", error.response?.data || error.message);
    throw error;
  }
};

// OSV Dependency Scan
export const scanDependencies = async (packages) => {
  try {
        const csrfToken = localStorage.getItem("csrf_token");
    
    const response = await axios.post(`${API_BASE_URL}/scan_dependencies`,
     { packages: packages },
     {
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      withCredentials: true,
    }
  );
    return response.data;
  } catch (error) {
    console.error("OSV API scan error:", error.response?.data || error.message);
    throw error;
  }
};

export const getEPSSData = async (advisories) => {
  try {
    const csrfToken = localStorage.getItem("csrf_token");

    const response = await axios.post(
      `${API_BASE_URL}/scan_epss`,
       advisories ,
      {
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken,
        },
        withCredentials: true,
      }
    );

    return response.data.results || [];
  } catch (error) {
    console.error("EPSS enrichment error:", error.response?.data || error.message);
    throw error;
  }
};


// Enrich with HuggingFace API for Risk Classification
export const enrichRisks = async (epssResults) => {
  try {
    const response = await axios.post(`${API_BASE_URL}/enrich_risks`, {
      advisories: epssResults,
    });

    if (response.data.error && response.data.error.includes("You have exceeded your monthly Hugging Face API credits")) {
      console.warn("You have exceeded your monthly Hugging Face API credits. The program will continue running without risk enrichment.");
      alert("Hugging Face API quota exceeded. The program will continue, but risk enrichment data is unavailable.");
      return epssResults; // Return the original data if no enrichment is available
    }

    // Ensure that we return an array, even if the results are not available
    const enrichedData = response.data.results || [];
    if (!Array.isArray(enrichedData)) {
      console.warn("Invalid enrichment data format received: ", response.data);
      return epssResults;
    }

    return enrichedData;
  } catch (error) {
    console.error("Risk enrichment error:", error.response?.data || error.message);
    alert("An error occurred while enriching risk data. The program will continue running.");
    return epssResults;
  }
};

// Function to trigger a threat alert (send to backend)
export const triggerAlert = async (threatName, riskScore, description) => {
  try {
    const response = await axios.post(`${API_BASE_URL}/process_threat`, {
      threat_name: threatName,
      risk_score: riskScore,
      description: description
    });
    alert(response.data.message);
  } catch (error) {

  }
};