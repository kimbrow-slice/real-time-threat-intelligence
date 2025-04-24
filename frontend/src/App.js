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
    <div className="container">
    <div className="login-container">
  <div className="login-card">
    <h1 className="login-title">Shop Smart Solutions
    </h1>
    <h5 className="login-subtitle">
    Real Time Threat Intelligence SIEM
    </h5>

    <form className="login-form" onSubmit={loginForm}>
      {error && <p className="login-error">{error}</p>}

      <input
        type="text"
        className="login-input"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />

      <input
        type="password"
        className="login-input"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />

      <button type="submit" className="login-button">
        Login
      </button>
    </form>

    <p className="login-register">
      Don’t have an account? <Link to="/register">Register here</Link>
    </p>
  </div>
  </div>
  <footer className="footer">
  Copyright &copy; <strong><span>ShopSmartSolutions</span></strong> 2025
</footer>
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