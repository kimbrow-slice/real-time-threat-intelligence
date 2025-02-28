import React, { useState } from "react";
import { Routes, Route, Navigate, useNavigate } from "react-router-dom";
import "./App.css";

import Dashboard from "./dashboard"; 

function LoginPage() {
  const [username, setUsername] = useState(""); //  Define username state
  const [password, setPassword] = useState(""); // Define password state
  const [error, setError] = useState(""); //  Define error state
  const navigate = useNavigate(); //  Define navigate function
  const API_URL = process.env.REACT_APP_API_URL || "http://127.0.0.1:5000";  
  console.log("Loaded API URL from .env:", process.env.REACT_APP_API_URL); // Debugging statement


  const loginForm = async (e) => {
    e.preventDefault();
  
    if (!username || !password) {
      alert("Both fields must be completed!"); // Alert user if they input no username or password
      return;
    }
  
    try {
      console.log("API URL:", process.env.REACT_APP_API_URL); // Debugging statement
  
      const response = await fetch(`${process.env.REACT_APP_API_URL}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        credentials: "include", // Ensures cookies & sessions work || TODO: Include bcypt to provide more cookie security
        body: JSON.stringify({ username, password }),
      });
      
      const text = await response.text();
      console.log("Raw response from Flask:", text); // Debugging statement
  
      const data = JSON.parse(text);
      console.log("Parsed JSON:", data); // Debugging statement
  
      if (response.ok && data.redirect) {
        console.log("Redirecting to:", data.redirect);
        navigate(data.redirect);
      } else {
        throw new Error(data.error || "Login failed");
      }
    } catch (err) {
      console.error("Fetch error:", err); // Debugging statement
      setError("Could not connect to server. Ensure Flask is running.");
    }
  };
  

  
 // Main content
  return (
    <div className="App">
      <header className="App-header">
        <h1>Real Time Threat Intelligence</h1>
        <h5>This application provides real-time analysis of current threats.</h5>

        <div className="loginForm">
          <form onSubmit={loginForm}>
            {error && <p style={{ color: "red" }}>{error}</p>}
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <input type="submit" value="Login" />
          </form>
        </div>
      </header>
    </div>
  );
}

function App() {
  return (
    <Routes>
      <Route path="/" element={<LoginPage />} />
      <Route path="/dashboard" element={<Dashboard />} />
      <Route path="*" element={<Navigate to="/" />} /> {/* Redirect unknown routes */}
    </Routes>
  );
}

export default App;
