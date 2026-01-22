# Baseline Normal Activity Logs

## Purpose
These logs represent NORMAL system activity before any attacks.

## Files

### baseline_auth_20260123.log
- **Captured:** January 23, 2026
- **Activity:** Normal SSH login and logout
- **User:** kali
- **Source:** localhost (127.0.0.1)
- **Events:** 
  - Login successful
  - Commands executed
  - Logout

**Pattern:**
- Single login attempt → Success
- ~30 seconds of activity
- Clean logout
- No failures or errors

### baseline_syslog_20260123.log
- **Captured:** January 23, 2026
- **Activity:** Normal system operations
- **Events:**
  - Service starts
  - Scheduled tasks
  - Regular system processes

**Pattern:**
- Predictable timing
- Expected services
- No anomalies

## Comparison Use

These logs will be compared against attack logs to identify:
- Volume differences (normal: low, attack: high)
- Speed differences (normal: slow, attack: fast)
- Success rate (normal: high, attack: low)
- Pattern differences (normal: irregular, attack: systematic)

---
**Baseline established:** January 23, 2026
