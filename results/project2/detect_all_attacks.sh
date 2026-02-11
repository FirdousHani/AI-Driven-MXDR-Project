#!/bin/bash
# Master Threat Detection Script - Day 5
# Checks for all three attack types

echo "╔════════════════════════════════════════════╗"
echo "║   MASTER THREAT DETECTION SYSTEM          ║"
echo "║   Project 2 - All Attack Types            ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# Check time window
TIME_WINDOW="24 hours ago"

echo "[*] Scanning logs from last 24 hours..."
echo ""

# ==========================================
# 1. PORT SCAN DETECTION
# ==========================================
echo "┌─────────────────────────────────────┐"
echo "│ 1. PORT SCAN DETECTION              │"
echo "└─────────────────────────────────────┘"

port_scans=$(sudo journalctl --since "$TIME_WINDOW" 2>/dev/null | grep -c "COMMAND.*nmap" || echo 0)

if [ "$port_scans" -gt 0 ]; then
    echo "⚠️  PORT SCAN DETECTED!"
    echo "   Count: $port_scans execution(s)"
    echo ""
    echo "   Evidence:"
    sudo journalctl --since "$TIME_WINDOW" 2>/dev/null | grep "COMMAND.*nmap" | tail -3
else
    echo "✅ No port scans detected"
fi
echo ""

# ==========================================
# 2. BRUTE FORCE DETECTION
# ==========================================
echo "┌─────────────────────────────────────┐"
echo "│ 2. BRUTE FORCE DETECTION            │"
echo "└─────────────────────────────────────┘"

failed_logins=$(sudo journalctl -u ssh --since "$TIME_WINDOW" 2>/dev/null | grep -c "Failed password" || echo 0)

if [ "$failed_logins" -gt 5 ]; then
    echo "⚠️  BRUTE FORCE ATTACK DETECTED!"
    echo "   Failed login attempts: $failed_logins"
    echo ""
    echo "   Top targeted users:"
    sudo journalctl -u ssh --since "$TIME_WINDOW" 2>/dev/null | grep "Failed password" | awk '{print $11}' | sort | uniq -c | sort -rn | head -3
    echo ""
    echo "   Top attacking IPs:"
    sudo journalctl -u ssh --since "$TIME_WINDOW" 2>/dev/null | grep "Failed password" | awk '{print $13}' | sort | uniq -c | sort -rn | head -3
else
    echo "✅ No brute force detected ($failed_logins failed logins)"
fi
echo ""

# ==========================================
# 3. VULNERABILITY SCAN DETECTION
# ==========================================
echo "┌─────────────────────────────────────┐"
echo "│ 3. VULNERABILITY SCAN DETECTION     │"
echo "└─────────────────────────────────────┘"

if [ -f /var/log/apache2/access.log ]; then
    total_requests=$(sudo wc -l < /var/log/apache2/access.log 2>/dev/null || echo 0)
    error_404=$(sudo grep -c " 404 " /var/log/apache2/access.log 2>/dev/null || echo 0)
    
    if [ "$total_requests" -gt 0 ]; then
        error_rate=$((error_404 * 100 / total_requests))
    else
        error_rate=0
    fi
    
    nikto_requests=$(sudo grep -c "Nikto" /var/log/apache2/access.log 2>/dev/null || echo 0)
    
    if [ "$error_rate" -gt 50 ] || [ "$nikto_requests" -gt 0 ]; then
        echo "⚠️  VULNERABILITY SCAN DETECTED!"
        echo "   Total HTTP requests: $total_requests"
        echo "   404 errors: $error_404 ($error_rate%)"
        echo "   Scanner signatures: $nikto_requests"
        echo ""
        echo "   Suspicious paths requested:"
        sudo grep " 404 " /var/log/apache2/access.log 2>/dev/null | awk '{print $7}' | grep -E "admin|backup|config|test|phpmyadmin" | sort | uniq | head -5
    else
        echo "✅ No vulnerability scans detected"
        echo "   (404 error rate: $error_rate%)"
    fi
else
    echo "ℹ️  Web server not running or no logs found"
fi
echo ""

# ==========================================
# SUMMARY
# ==========================================
echo "╔════════════════════════════════════════════╗"
echo "║              THREAT SUMMARY                ║"
echo "╚════════════════════════════════════════════╝"

threat_count=0
[ "$port_scans" -gt 0 ] && ((threat_count++))
[ "$failed_logins" -gt 5 ] && ((threat_count++))
[ "$error_rate" -gt 50 ] || [ "$nikto_requests" -gt 0 ] && ((threat_count++))

if [ "$threat_count" -eq 0 ]; then
    echo "✅ System secure - no attacks detected"
elif [ "$threat_count" -eq 1 ]; then
    echo "⚠️  1 attack type detected"
elif [ "$threat_count" -eq 2 ]; then
    echo "⚠️  2 attack types detected - ELEVATED THREAT"
else
    echo "🚨 3 attack types detected - ACTIVE ATTACK CAMPAIGN"
    echo "   This indicates coordinated reconnaissance!"
fi

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║          RECOMMENDED ACTIONS               ║"
echo "╚════════════════════════════════════════════╝"

if [ "$threat_count" -gt 0 ]; then
    echo "1. Review detailed logs above"
    echo "2. Block attacking IP addresses"
    echo "3. Enable fail2ban (auto-blocking)"
    echo "4. Update/patch vulnerable services"
    echo "5. Alert security team"
    echo "6. Investigate if authorized pen test"
else
    echo "Continue monitoring. All systems normal."
fi

echo ""
echo "Detection complete: $(date)"
echo ""
