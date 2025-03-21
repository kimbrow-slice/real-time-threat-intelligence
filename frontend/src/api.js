import axios from 'axios';

const VT_API_URL = process.env.REACT_APP_VIRUSTOTAL_API_URL;
const SHODAN_API_URL = process.env.REACT_APP_SHODAN_API_URL;
const API_BASE_URL = 'http://localhost:5000'; // Update if hosted elsewhere

// Helper to get user_id from localStorage
const getUserId = () => localStorage.getItem("user_id");

// Scan IP using VirusTotal API
export const scanIpAddress = async (ipAddress) => {
  try {
    const userId = getUserId();
    const response = await axios.get(
      `${VT_API_URL}?ip=${ipAddress}&user_id=${userId}`
    );
    return response.data;
  } catch (error) {
    console.error("VirusTotal API error:", error);
    throw error;
  }
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

// Register a new user
export const registerUser = async (username, password) => {
  try {
    const response = await axios.post(`${API_BASE_URL}/register`, {
      username,
      password,
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
