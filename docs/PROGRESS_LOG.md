---

## Week 2: Offensive Security & Attack Simulation

### Day 1 - January 23, 2026 ✅

**Project Phase:** Project 2 - Day 1: Attack Lab Setup

**What I Did:**
- ✅ Created Project 2 folder structure (attack_logs, normal_logs, signatures, results)
- ✅ Wrote comprehensive Project 2 overview documentation
- ✅ Verified attack tools installation (nmap, hydra, nikto all present)
- ✅ Configured SSH service as attack target
- ✅ Captured baseline "normal" activity logs for comparison
- ✅ Created attack safety checklist
- ✅ Documented legal and ethical guidelines

**Lab Configuration:**
```
Attack Machine: Kali Linux
IP Address: 192.168.1.50
Target: localhost (127.0.0.1)
Services: SSH (port 22)
```

**What I LEARNED (Security Concepts):**

1. **Attack Lab Fundamentals:**
   - Must have controlled, isolated environment
   - Need baseline "normal" logs for comparison
   - Attacking localhost = safe for learning
   - Always document everything

2. **Legal & Ethical Framework:**
   - NEVER attack systems without permission = felony
   - Pen testing requires written authorization
   - Educational use on own systems = legal
   - Intent matters: learning vs malicious

3. **Attack Kill Chain (Overview):**
```
   1. Reconnaissance (scan for info)
   2. Weaponization (prepare exploit)
   3. Delivery (send exploit)
   4. Exploitation (execute)
   5. Installation (persistence)
   6. Command & Control (maintain access)
   7. Actions on Objectives (steal data)
   
   Project 2 will cover phases 1-2
```

4. **Normal vs Attack Hypothesis:**
```
   NORMAL activity:
   - Low volume (1-5 events/min)
   - Successful operations
   - Irregular timing (human behavior)
   - Predictable patterns
   
   ATTACK activity (predicted):
   - High volume (100+ events/min)
   - Many failures
   - Regular timing (automated)
   - Systematic patterns
   
   I'll verify this hypothesis in Days 2-5!
```

**Baseline Captured:**

Captured normal activity logs:
- `baseline_auth_20260123.log` - Normal SSH login/logout
- `baseline_syslog_20260123.log` - Normal system operations

**Normal Activity Pattern:**
- 1 SSH login → success
- ~30 seconds of activity
- Clean logout
- No failures

**This will be compared against attack logs to spot differences!**

**Tools Verified:**
- ✅ nmap (version 7.94) - Network scanner
- ✅ hydra (version 9.5) - Password cracker
- ✅ nikto (version 2.5.0) - Web vulnerability scanner
- ✅ SSH service - Attack target ready

**Challenges:**
- Understanding why baseline logs matter
- Ensuring environment is truly isolated
- Remembering this is LEGAL because it's my own system

**Solutions:**
- Baseline = reference point to measure "abnormal"
- Using localhost = no network exposure
- Documented authorization (I own this machine!)

**What NOT to Memorize:**
- SSH configuration commands
- Exact tool versions
- File paths

**What TO Remember:**
- **Attack lab must be isolated and authorized**
- **Baseline logs = normal behavior reference**
- **Attack kill chain has 7 phases**
- **Attacking without permission = ILLEGAL (Computer Fraud and Abuse Act)**

**Key Security Insight:**
"You can't detect abnormal if you don't know what normal looks like. Baseline logs are critical for threat detection!"

**Career Skill Developed:**
- Lab setup and configuration (foundational for pen testing)
- Documentation and safety protocols
- Legal and ethical awareness

**GitHub Activity:**
- Files created: 8
- Folders created: 4
- Commits: 1
- Total lines documented: ~200

**Next Steps:**
- [ ] Day 2: Run port scan with nmap
- [ ] Capture attack logs
- [ ] Compare to baseline
- [ ] Document port scan signature
- [ ] Create detection rule

**Time Spent:** 2 hours

**Mood:** 🔥 Excited! Lab is ready. Time to become the attacker (ethically!)

**Quote of the Day:**
"To defend against attackers, you must first understand how they think and operate. Today I built the foundation to safely learn both sides of cybersecurity."

---

### Statistics Update

| Week | Days Worked | Total Hours | GitHub Commits | Status |
|------|-------------|-------------|----------------|---------|
| 1 (Project 1) | 7 | ~8 | 7 | ✅ Complete |
| 2 (Project 2) | 1 | 2 | 1 | 🔄 In Progress |

---
