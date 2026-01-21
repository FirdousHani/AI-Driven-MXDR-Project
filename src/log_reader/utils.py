import re
from datetime import datetime
from typing import Dict, List, Optional

def parse_log_line(line: str) -> Optional[Dict[str, str]]:
    """
    Parse a single auth.log line into structured components.
    
    Args:
        line: A single line from auth.log
        
    Returns:
        Dictionary with parsed components or None if parsing fails
    """
    # Pattern: Month Day Time Hostname Process: Message
    pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.+)$'
    
    match = re.match(pattern, line.strip())
    if not match:
        return None
    
    timestamp, hostname, process, message = match.groups()
    
    return {
        'timestamp': timestamp,
        'hostname': hostname,
        'process': process,
        'message': message
    }

def format_log_entry(entry: Dict[str, str], colorize: bool = True) -> str:
    """
    Format a parsed log entry into human-readable format.
    
    Args:
        entry: Dictionary containing parsed log components
        colorize: Whether to add ANSI color codes
        
    Returns:
        Formatted string representation
    """
    # ANSI color codes
    CYAN = '\033[96m' if colorize else ''
    GREEN = '\033[92m' if colorize else ''
    YELLOW = '\033[93m' if colorize else ''
    BLUE = '\033[94m' if colorize else ''
    RESET = '\033[0m' if colorize else ''
    GRAY = '\033[90m' if colorize else ''
    
    formatted = f"""
{CYAN}Timestamp:{RESET}  {entry['timestamp']} {GRAY}← When it happened{RESET}
{GREEN}Hostname:{RESET}   {entry['hostname']} {GRAY}← Which server{RESET}
{YELLOW}Process:{RESET}    {entry['process']}: {GRAY}← What service{RESET}
{BLUE}Message:{RESET}    {entry['message']} {GRAY}← What happened{RESET}
"""
    return formatted

def parse_auth_log(log_file_path: str, output_file: Optional[str] = None, 
                   colorize: bool = True) -> List[Dict[str, str]]:
    """
    Parse an entire auth.log file and display in human-readable format.
    
    Args:
        log_file_path: Path to the auth.log file
        output_file: Optional path to save formatted output
        colorize: Whether to use colors in console output
        
    Returns:
        List of parsed log entries
    """
    parsed_entries = []
    formatted_output = []
    
    try:
        with open(log_file_path, 'r') as f:
            lines = f.readlines()
        
        print(f"\n{'='*70}")
        print(f"  AUTH.LOG PARSER - Processing {len(lines)} log entries")
        print(f"{'='*70}\n")
        
        for i, line in enumerate(lines, 1):
            if not line.strip():
                continue
                
            entry = parse_log_line(line)
            if entry:
                parsed_entries.append(entry)
                formatted = format_log_entry(entry, colorize)
                formatted_output.append(formatted)
                
                # Print to console
                print(f"[Entry {i}]")
                print(formatted)
                print("-" * 70)
            else:
                print(f"[Warning] Could not parse line {i}: {line.strip()}\n")
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                f.write(f"AUTH.LOG PARSER OUTPUT\n")
                f.write(f"{'='*70}\n\n")
                for i, formatted in enumerate(formatted_output, 1):
                    f.write(f"[Entry {i}]\n")
                    # Remove color codes for file output
                    clean_output = re.sub(r'\033\[\d+m', '', formatted)
                    f.write(clean_output)
                    f.write("-" * 70 + "\n")
            print(f"\n✓ Output saved to: {output_file}")
        
        print(f"\n{'='*70}")
        print(f"  Successfully parsed {len(parsed_entries)} entries")
        print(f"{'='*70}\n")
        
        return parsed_entries
        
    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found")
        return []
    except Exception as e:
        print(f"Error processing log file: {e}")
        return []

def filter_failed_logins(entries: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Filter entries for failed login attempts."""
    return [e for e in entries if 'Failed password' in e['message'] or 
            'Invalid user' in e['message']]

def filter_successful_logins(entries: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Filter entries for successful login attempts."""
    return [e for e in entries if 'Accepted password' in e['message']]

def get_unique_ips(entries: List[Dict[str, str]]) -> List[str]:
    """Extract unique IP addresses from log entries."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = set()
    
    for entry in entries:
        found_ips = re.findall(ip_pattern, entry['message'])
        ips.update(found_ips)
    
    return sorted(list(ips))

# Example usage
if __name__ == "__main__":
    # Path to your auth.log file (relative to project root)
    log_path = "data/sample_logs/auth.log"
    
    # Parse the log file
    entries = parse_auth_log(log_path, output_file="data/formatted_auth.log")
    
    # Additional analysis
    if entries:
        print("\n" + "="*70)
        print("  SECURITY ANALYSIS")
        print("="*70 + "\n")
        
        failed = filter_failed_logins(entries)
        successful = filter_successful_logins(entries)
        unique_ips = get_unique_ips(entries)
        
        print(f"Failed login attempts: {len(failed)}")
        print(f"Successful logins: {len(successful)}")
        print(f"Unique IP addresses: {len(unique_ips)}")
        print(f"\nIP Addresses involved:")
        for ip in unique_ips:
            print(f"  • {ip}")
