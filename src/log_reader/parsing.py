import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, Counter

def parse_log_line(line: str) -> Optional[Dict[str, str]]:
    """
    Parse a single auth.log line into structured components.
    
    Args:
        line: A single line from auth.log
        
    Returns:
        Dictionary with parsed components or None if parsing fails
    """
    pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.+)$'
    
    match = re.match(pattern, line.strip())
    if not match:
        return None
    
    timestamp, hostname, process, message = match.groups()
    
    # Extract IP address if present
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_match = re.search(ip_pattern, message)
    ip_address = ip_match.group(0) if ip_match else None
    
    # Classify event type
    event_type = classify_event(message)
    
    # Extract username if present
    username = extract_username(message)
    
    return {
        'timestamp': timestamp,
        'hostname': hostname,
        'process': process,
        'message': message,
        'ip_address': ip_address,
        'event_type': event_type,
        'username': username
    }

def classify_event(message: str) -> str:
    """
    Classify the type of security event.
    
    Args:
        message: Log message
        
    Returns:
        Event classification string
    """
    classifications = {
        'FAILED_LOGIN': ['Failed password', 'authentication failure'],
        'SUCCESSFUL_LOGIN': ['Accepted password', 'Accepted publickey'],
        'INVALID_USER': ['Invalid user', 'illegal user'],
        'BRUTE_FORCE': ['Failed password'],  # Will be upgraded based on frequency
        'PRIVILEGE_ESCALATION': ['sudo:', 'su:', 'COMMAND='],
        'FIREWALL_BLOCK': ['UFW BLOCK', 'DENY'],
        'CONNECTION_CLOSED': ['Connection closed', 'Connection reset'],
        'SESSION_OPENED': ['session opened', 'New session'],
        'SESSION_CLOSED': ['session closed'],
    }
    
    for event_type, keywords in classifications.items():
        if any(keyword in message for keyword in keywords):
            return event_type
    
    return 'UNKNOWN'

def extract_username(message: str) -> Optional[str]:
    """Extract username from log message."""
    patterns = [
        r'for (?:invalid user )?(\w+) from',
        r'user (\w+)',
        r'^(\w+) :',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message)
        if match:
            return match.group(1)
    
    return None

def format_log_entry(entry: Dict[str, str], colorize: bool = True) -> str:
    """Format a parsed log entry into human-readable format."""
    CYAN = '\033[96m' if colorize else ''
    GREEN = '\033[92m' if colorize else ''
    YELLOW = '\033[93m' if colorize else ''
    BLUE = '\033[94m' if colorize else ''
    RED = '\033[91m' if colorize else ''
    MAGENTA = '\033[95m' if colorize else ''
    RESET = '\033[0m' if colorize else ''
    GRAY = '\033[90m' if colorize else ''
    
    # Color code based on threat level
    threat_color = RED if entry['event_type'] in ['FAILED_LOGIN', 'INVALID_USER', 'BRUTE_FORCE'] else BLUE
    
    formatted = f"""
{CYAN}Timestamp:{RESET}   {entry['timestamp']} {GRAY}← When it happened{RESET}
{GREEN}Hostname:{RESET}    {entry['hostname']} {GRAY}← Which server{RESET}
{YELLOW}Process:{RESET}     {entry['process']}: {GRAY}← What service{RESET}
{MAGENTA}Event Type:{RESET}  {entry['event_type']} {GRAY}← Classification{RESET}
{threat_color}Message:{RESET}     {entry['message']} {GRAY}← What happened{RESET}"""
    
    if entry['ip_address']:
        formatted += f"\n{RED}IP Address:{RESET}  {entry['ip_address']} {GRAY}← Source IP{RESET}"
    
    if entry['username']:
        formatted += f"\n{CYAN}Username:{RESET}    {entry['username']} {GRAY}← Target user{RESET}"
    
    return formatted + "\n"

def detect_brute_force(entries: List[Dict[str, str]], threshold: int = 3, 
                       time_window: int = 300) -> Dict[str, List[Dict]]:
    """
    Detect brute force attacks (multiple failed logins from same IP).
    
    Args:
        entries: List of parsed log entries
        threshold: Number of failed attempts to classify as brute force
        time_window: Time window in seconds (default 5 minutes)
        
    Returns:
        Dictionary of suspicious IPs and their attempts
    """
    from datetime import datetime
    
    ip_attempts = defaultdict(list)
    
    for entry in entries:
        if entry['event_type'] in ['FAILED_LOGIN', 'INVALID_USER'] and entry['ip_address']:
            ip_attempts[entry['ip_address']].append(entry)
    
    suspicious_ips = {}
    for ip, attempts in ip_attempts.items():
        if len(attempts) >= threshold:
            suspicious_ips[ip] = {
                'attempts': attempts,
                'count': len(attempts),
                'usernames': list(set([a['username'] for a in attempts if a['username']])),
                'threat_level': 'HIGH' if len(attempts) >= 5 else 'MEDIUM'
            }
    
    return suspicious_ips

def analyze_privilege_escalation(entries: List[Dict[str, str]]) -> List[Dict]:
    """Analyze privilege escalation attempts."""
    escalations = []
    
    for entry in entries:
        if entry['event_type'] == 'PRIVILEGE_ESCALATION':
            escalations.append({
                'timestamp': entry['timestamp'],
                'username': entry['username'],
                'command': entry['message'],
                'ip_address': entry['ip_address']
            })
    
    return escalations

def get_event_timeline(entries: List[Dict[str, str]]) -> Dict[str, List[Dict]]:
    """Create a timeline of events grouped by IP address."""
    timeline = defaultdict(list)
    
    for entry in entries:
        if entry['ip_address']:
            timeline[entry['ip_address']].append({
                'timestamp': entry['timestamp'],
                'event_type': entry['event_type'],
                'message': entry['message'],
                'username': entry['username']
            })
    
    return dict(timeline)

def get_event_statistics(entries: List[Dict[str, str]]) -> Dict:
    """Generate comprehensive event statistics."""
    stats = {
        'total_events': len(entries),
        'by_type': Counter([e['event_type'] for e in entries]),
        'by_ip': Counter([e['ip_address'] for e in entries if e['ip_address']]),
        'by_username': Counter([e['username'] for e in entries if e['username']]),
        'unique_ips': len(set([e['ip_address'] for e in entries if e['ip_address']])),
        'unique_users': len(set([e['username'] for e in entries if e['username']]))
    }
    
    return stats

def classify_ip_reputation(ip: str, attempts: Dict) -> str:
    """
    Classify IP reputation based on behavior.
    
    Returns: MALICIOUS, SUSPICIOUS, or UNKNOWN
    """
    count = attempts['count']
    usernames = attempts['usernames']
    
    # Check for common attack patterns
    common_targets = ['admin', 'root', 'test', 'user', 'guest']
    targeting_common = any(u in common_targets for u in usernames)
    
    if count >= 5 or (count >= 3 and targeting_common):
        return 'MALICIOUS'
    elif count >= 3:
        return 'SUSPICIOUS'
    
    return 'UNKNOWN'

def parse_auth_log(log_file_path: str, output_file: Optional[str] = None, 
                   colorize: bool = True) -> List[Dict[str, str]]:
    """
    Parse an entire auth.log file with advanced security analysis.
    """
    parsed_entries = []
    formatted_output = []
    console_output = []
    
    try:
        with open(log_file_path, 'r') as f:
            lines = f.readlines()
        
        header = f"\n{'='*70}\n  AUTH.LOG SECURITY ANALYZER - Processing {len(lines)} log entries\n{'='*70}\n"
        print(header)
        console_output.append(header)
        
        for i, line in enumerate(lines, 1):
            if not line.strip():
                continue
                
            entry = parse_log_line(line)
            if entry:
                parsed_entries.append(entry)
                formatted = format_log_entry(entry, colorize)
                formatted_output.append(formatted)
                
                entry_header = f"[Entry {i}]\n"
                print(entry_header, end='')
                print(formatted)
                print("-" * 70)
                
                console_output.append(entry_header)
                console_output.append(formatted)
                console_output.append("-" * 70 + "\n")
            else:
                warning = f"[Warning] Could not parse line {i}: {line.strip()}\n"
                print(warning)
                console_output.append(warning)
        
        success_msg = f"\n{'='*70}\n  Successfully parsed {len(parsed_entries)} entries\n{'='*70}\n"
        print(success_msg)
        console_output.append(success_msg)
        
        # Advanced Security Analysis (capture output)
        analysis_output = perform_security_analysis(parsed_entries, colorize, return_output=True)
        console_output.extend(analysis_output)
        
        # Save complete output to file
        if output_file:
            with open(output_file, 'w') as f:
                # Write everything without color codes
                for line in console_output:
                    clean_line = re.sub(r'\033\[\d+m', '', line)
                    f.write(clean_line)
            
            save_msg = f"\n✓ Complete analysis saved to: {output_file}\n"
            print(save_msg)
        
        return parsed_entries
        
    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found")
        return []
    except Exception as e:
        print(f"Error processing log file: {e}")
        return []

def perform_security_analysis(entries: List[Dict[str, str]], colorize: bool = True, return_output: bool = False):
    """Perform comprehensive security analysis."""
    RED = '\033[91m' if colorize else ''
    YELLOW = '\033[93m' if colorize else ''
    GREEN = '\033[92m' if colorize else ''
    CYAN = '\033[96m' if colorize else ''
    MAGENTA = '\033[95m' if colorize else ''
    BOLD = '\033[1m' if colorize else ''
    RESET = '\033[0m' if colorize else ''
    
    output = []
    
    def print_and_capture(text):
        print(text)
        if return_output:
            output.append(text + "\n")
    
    print_and_capture("\n" + "="*70)
    print_and_capture(f"{BOLD}  🔒 SECURITY THREAT ANALYSIS{RESET}")
    print_and_capture("="*70 + "\n")
    
    # 1. Event Statistics
    stats = get_event_statistics(entries)
    print_and_capture(f"{CYAN}📊 Event Statistics:{RESET}")
    print_and_capture(f"  Total Events: {stats['total_events']}")
    print_and_capture(f"  Unique IP Addresses: {stats['unique_ips']}")
    print_and_capture(f"  Unique Usernames: {stats['unique_users']}\n")
    
    print_and_capture(f"{CYAN}Event Type Distribution:{RESET}")
    for event_type, count in stats['by_type'].most_common():
        print_and_capture(f"  • {event_type}: {count}")
    
    # 2. Brute Force Detection
    print_and_capture(f"\n{RED}🚨 Brute Force Attack Detection:{RESET}")
    suspicious_ips = detect_brute_force(entries, threshold=3)
    
    if suspicious_ips:
        print_and_capture(f"  {BOLD}Found {len(suspicious_ips)} suspicious IP(s):{RESET}\n")
        
        for ip, data in suspicious_ips.items():
            reputation = classify_ip_reputation(ip, data)
            color = RED if reputation == 'MALICIOUS' else YELLOW
            
            print_and_capture(f"  {color}⚠ IP: {ip}{RESET}")
            print_and_capture(f"    • Threat Level: {color}{data['threat_level']}{RESET}")
            print_and_capture(f"    • Reputation: {color}{reputation}{RESET}")
            print_and_capture(f"    • Failed Attempts: {data['count']}")
            print_and_capture(f"    • Targeted Usernames: {', '.join(data['usernames']) if data['usernames'] else 'N/A'}")
            print_and_capture(f"    • Attack Pattern: {'Username enumeration' if len(data['usernames']) > 2 else 'Targeted attack'}")
            print_and_capture("")
    else:
        print_and_capture(f"  {GREEN}✓ No brute force patterns detected{RESET}\n")
    
    # 3. Privilege Escalation
    print_and_capture(f"{YELLOW}⚡ Privilege Escalation Analysis:{RESET}")
    escalations = analyze_privilege_escalation(entries)
    
    if escalations:
        print_and_capture(f"  Found {len(escalations)} privilege escalation event(s):\n")
        for esc in escalations:
            print_and_capture(f"  • Timestamp: {esc['timestamp']}")
            print_and_capture(f"    User: {esc['username']}")
            print_and_capture(f"    Command: {esc['command']}")
            print_and_capture("")
    else:
        print_and_capture(f"  {GREEN}✓ No privilege escalation detected{RESET}\n")
    
    # 4. Event Timeline by IP
    print_and_capture(f"{MAGENTA}📅 Event Timeline Correlation:{RESET}")
    timeline = get_event_timeline(entries)
    
    for ip, events in sorted(timeline.items(), key=lambda x: len(x[1]), reverse=True):
        print_and_capture(f"\n  IP: {ip} ({len(events)} events)")
        for event in events[:5]:  # Show first 5 events
            print_and_capture(f"    • [{event['timestamp']}] {event['event_type']}: {event['username'] or 'N/A'}")
        if len(events) > 5:
            print_and_capture(f"    ... and {len(events) - 5} more events")
    
    # 5. Top Targeted Usernames
    print_and_capture(f"\n{CYAN}👤 Most Targeted Usernames:{RESET}")
    for username, count in stats['by_username'].most_common(5):
        print_and_capture(f"  • {username}: {count} attempts")
    
    # 6. Recommendations
    print_and_capture(f"\n{BOLD}💡 Security Recommendations:{RESET}")
    
    if suspicious_ips:
        print_and_capture(f"  {RED}[CRITICAL]{RESET} Block the following IPs immediately:")
        for ip in suspicious_ips.keys():
            print_and_capture(f"    • {ip}")
    
    failed_count = stats['by_type'].get('FAILED_LOGIN', 0) + stats['by_type'].get('INVALID_USER', 0)
    if failed_count > 5:
        print_and_capture(f"  {YELLOW}[WARNING]{RESET} High number of failed login attempts ({failed_count})")
        print_and_capture(f"    → Enable fail2ban or similar intrusion prevention")
        print_and_capture(f"    → Implement rate limiting on SSH")
    
    if escalations:
        print_and_capture(f"  {YELLOW}[WARNING]{RESET} Monitor privilege escalation activities")
        print_and_capture(f"    → Review sudo access policies")
        print_and_capture(f"    → Enable sudo command logging")
    
    print_and_capture(f"\n{'='*70}\n")
    
    if return_output:
        return output

# Example usage
if __name__ == "__main__":
    log_path = "data/sample_logs/auth.log"
    entries = parse_auth_log(log_path, output_file="data/sample_logs/formatted_auth.log")
