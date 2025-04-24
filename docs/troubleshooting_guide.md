# Troubleshooting & Maintenance Guide

## Common Issues & Fixes

### 1. System Not Starting
**Cause**: Configuration error or service not running.

**Fix**:
- Check system logs: `journalctl -xe` or `/var/log/syslog`
- Ensure required services are running: `systemctl status <service_name>`
- Restart the service: `sudo systemctl restart <service_name>`
---

### 2. Network Connectivity Issues
**Cause**: Misconfigured firewall rules or IP conflict.  

**Fix**:
- Verify IP settings: `ip a` and `ping` test
- Check firewall: `sudo ufw status` or relevant tool
- Ensure proper settings 
---

### 3. Web App Not Responding
**Cause**: Web server down or backend service failure.  

**Fix**:
- Check NGINX/Apache logs: `/var/log/nginx/error.log`
- Restart web server: `sudo systemctl restart nginx`
- Restart app backend (Node, Python): `pm2 restart all` or equivalent
---

### 4. OpenVAS Scan Fails
**Cause**: Incorrect target IP or scanner not initialized.  

**Fix**:
- Check again the target configuration
- Start scanner: `sudo openvas-start`
- Verify logs for scanner status
---

### 5. API Requests to VirusTotal Fail  
**Cause**: API key issue, rate limiting, or incorrect endpoint. 

**Fix**:
- Verify API key is correctly set in environment variables.  
- Check VirusTotal account limits and upgrade if necessary.  
- Use correct base URL: `https://www.virustotal.com/api/v3/`  
- Confirm headers include `x-apikey` and content-type if needed.
---

### 6. GPT-4 API Not Responding  
**Cause**: Invalid key, rate limits, or malformed request.  

**Fix**:
- Double-check API key and usage limits on OpenAI dashboard.  
- Validate request payload structure (model, prompt)  
- Use a retry mechanism for intermittent timeouts.
---

### 7. Front-End Not Fetching Data  
**Cause**: Broken API route, or client-side bug.

**Fix**:
- Make sure Flask API has proper CORS headers (`flask-cors`).  
- Check browser console and network tab for failed calls.  
- Ensure React is hitting the correct back-end endpoint (relative paths can be an issue in dev vs prod).
---

### 8. PostgreSQL Connection Issues  
**Cause**: Wrong credentials, DB service not running, or firewall block.  

**Fix**:
- Verify `DATABASE_URL` or connection string.  
- Make sure PostgreSQL is running: `sudo systemctl status postgresql`  
- Check DB logs for specific error messages.
---

## Maintenance Best Practices

- **Weekly**: Restart services during low-traffic hours to prevent memory leaks.
- **Monthly**: Check for and apply security patches and system updates.
- **Quarterly**: Audit firewall rules and VLAN settings.
- **Annually**: Review system documentation and update based on infrastructure changes.
- Rotate API keys for VirusTotal and OpenAI periodically.
- Monitor API usage to stay within limits and avoid service interruption.
- Regularly update the front-end dependencies (`npm audit fix`) and back-end packages (`pip list --outdated`).
- Backup the PostgreSQL database weekly using `pg_dump`.
---

## Tips for New Admins

- Always back up configurations before making changes.
- Use version control for configuration files when possible.
- Document every non-obvious change in the system logs.
- Monitor logs actively and set up alerts for critical failures.
---

## Getting Help

If you're stuck:
- Check internal documentation: `/docs/`
- Ask the admin team through email: `it-support@example.com`
- Refer to the upstream documentation for the third-party tools used

