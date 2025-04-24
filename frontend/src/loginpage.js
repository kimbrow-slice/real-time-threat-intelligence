import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./App.css";
import sha256 from 'crypto-js/sha256';


function LoginPage({ setAuthenticated }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();
  const hashedPassword = sha256(password).toString();

  const handleLogin = async (e) => {
    e.preventDefault();
    const response = await fetch("http://127.0.0.1:5000/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password: hashedPassword }),
    });

    const data = await response.json();
    if (response.ok) {
      setAuthenticated(true);
      navigate(data.redirect);
    } else {
      setError(data.error);
    }
  };

  return (
    

    <div className="login-container">
      <div className="header">
      <h2>Shop Smart Solutions SIEM</h2> 
      </div>
      <div className="login-card">
        <h2>Login Page</h2>
        {error && <div className="login-error">{error}</div>}
        <form onSubmit={handleLogin}>
          <input placeholder="Enter Your Username" value={username} onChange={(e) => setUsername(e.target.value)} />
          <input placeholder="Enter Your Password"value={password} onChange={(e) => setPassword(e.target.value)} />
          <button className="login-button" type="submit">Login</button>
        </form>
      </div>
    <footer className="footer">
        Copyright &copy; <strong><span>ShopSmartSolutions</span></strong> 2025
        </footer>
  </div>
  );
}

export default LoginPage;
