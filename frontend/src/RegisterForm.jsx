// src/RegisterForm.jsx
import React, { useState } from "react";

function RegisterForm() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Basic validation (optional)
    if (!username || !password) {
      setError("Username and password required");
      return;
    }

    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL}/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (response.ok) {
        // Registration successful
        setMessage(data.message || "User registered!");
        setError("");
      } else {
        // Registration failed
        setMessage("");
        setError(data.error || "Registration failed");
      }
    } catch (err) {
      setMessage("");
      setError("Could not connect to server. Ensure Flask is running.");
      console.error(err);
    }
  };

  return (
    <div style={{ margin: "1rem" }}>
      <h2>Register</h2>
      {message && <div style={{ color: "green" }}>{message}</div>}
      {error && <div style={{ color: "red" }}>{error}</div>}
      <form onSubmit={handleSubmit}>
        <div>
          <label>Username:</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter a username"
          />
        </div>
        <div style={{ marginTop: "0.5rem" }}>
          <label>Password:</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter a password"
          />
        </div>
        <button type="submit" style={{ marginTop: "1rem" }}>
          Register
        </button>
      </form>
    </div>
  );
}

export default RegisterForm;
