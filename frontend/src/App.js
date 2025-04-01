import React, { useState } from "react";
import { Routes, Route, Navigate, useNavigate, Link } from "react-router-dom";
import "./App.css";
import Dashboard from "./dashboard";
import Register from "./components/Register"; 

function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const loginForm = async (e) => {
    e.preventDefault();
  
    if (!username || !password) {
      setError("Both fields must be completed!");
      return;
    }
  
    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        credentials: "include",
        body: JSON.stringify({ username, password }),
      });
  
      const data = await response.json();
  
      if (response.ok && data.redirect) {
        // Save user_id to localStorage
        localStorage.setItem("user_id", data.user_id);
        navigate(data.redirect);
      } else {
        setError(data.error || "Login failed");
      }
    } catch (err) {
      setError("Could not connect to server. Ensure Flask is running.");
      console.error("Fetch error:", err);
    }
  };
  
  

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
          <p style={{ marginTop: "1rem" }}>
            Don’t have an account? <Link to="/register">Register here</Link>
          </p>
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
      <Route path="/register" element={<Register />} /> 
      <Route path="*" element={<Navigate to="/" />} />
    </Routes>
  );
}

export default App;
