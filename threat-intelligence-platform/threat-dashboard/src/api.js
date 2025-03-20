import axios from 'axios';

const VT_API_URL = process.env.REACT_APP_VIRUSTOTAL_API_URL;
const SHODAN_API_URL = process.env.REACT_APP_SHODAN_API_URL;

export const scanIpAddress = async (ipAddress) => {
  try {
    const response = await axios.get(`${VT_API_URL}?ip=${ipAddress}`);
    return response.data;
  } catch (error) {
    console.error("VirusTotal API error:", error);
    throw error;
  }
};

export const shodanScanIp = async (ipAddress) => {
  try {
    const response = await axios.get(`${SHODAN_API_URL}?ip=${ipAddress}`);
    return response.data;
  } catch (error) {
    console.error("Shodan API error:", error);
    throw error;
  }
};
