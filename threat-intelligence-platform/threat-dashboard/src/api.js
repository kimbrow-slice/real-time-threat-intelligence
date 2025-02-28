import axios from "axios";

const API_URL = process.env.REACT_APP_API_URL || "http://127.0.0.1:5000"; // Flask backend

// 
export const scanIpAddress = async (ipAddress) => {
  try {
    const url = `${API_URL}/scan_ip?ip=${ipAddress}`; 
    console.log("Making request to Flask backend:", url); // Debug statements

    const response = await axios.get(url);
    return response.data;
  } catch (error) {
    console.error("Flask API request error:", error); // Debug statements
    throw error;
  }
};
