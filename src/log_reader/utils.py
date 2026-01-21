"""
Log Format Analyzer - Day 2
Helps understand log structure by breaking it into parts
"""

def analyze_log_line(line):
    """
    Takes one log line and shows you its parts
    
    Think of it like a grammar teacher showing you:
    "The cat sat" = subject (cat) + verb (sat)
    
    We're doing the same for logs!
    """
    
    print(f"\n{'='*80}")
    print("ANALYZING LOG LINE:")
    print(f"{'='*80}")
    print(f"Raw: {line.strip()}\n")
    
    # Split by spaces (like cutting a sentence into words)
    parts = line.strip().split()
    
    print("Components (broken into pieces):")
    print("-" * 80)
    
    # Show each piece with a number
    for i, part in enumerate(parts):
        print(f"  [{i}] {part}")
    
    # Now explain what each piece means
    print("\n" + "="*80)
    print("INTERPRETATION (what it means):")
    print("="*80)
    
    # Usually log format is:
    # [0] Month, [1] Day, [2] Time = Timestamp
    # [3] = Hostname
    # [4] = Process
    # [5+] = Message
    
    print(f"  Timestamp:  {' '.join(parts[0:3])} ← When it happened")
    print(f"  Hostname:   {parts[3]} ← Which server")
    print(f"  Process:    {parts[4]} ← What service")
    print(f"  Message:    {' '.join(parts[5:])} ← What happened")
    print("="*80 + "\n")


def show_log_patterns():
    """
    Shows you common log formats you'll see
    
    Like a dictionary showing you different sentence structures
    """
    
    print("\n" + "="*80)
    print("COMMON LOG PATTERNS (What to look for)")
    print("="*80 + "\n")
    
    patterns = {
        "Authentication Logs (Login attempts)": {
            "Format": "Month Day Time hostname sshd[PID]: message",
            "Example": "Jan 19 10:23:15 server sshd[12345]: Failed password...",
            "What to look for": "Failed/Accepted, usernames, source IPs"
        },
        "Firewall Logs (Blocked traffic)": {
            "Format": "Month Day Time hostname kernel: [action] details",
            "Example": "Jan 19 11:20:00 server kernel: [UFW BLOCK] SRC=1.2.3.4",
            "What to look for": "BLOCK/ALLOW, source IPs, destination IPs"
        },
        "Sudo Logs (Admin commands)": {
            "Format": "Month Day Time hostname sudo: user : COMMAND=...",
            "Example": "Jan 19 11:15:30 server sudo: john : COMMAND=/bin/bash",
            "What to look for": "Who used sudo, what command they ran"
        }
    }
    
    for log_type, info in patterns.items():
        print(f"📋 {log_type}")
        print(f"   Format:  {info['Format']}")
        print(f"   Example: {info['Example']}")
        print(f"   Look for: {info['What to look for']}")
        print()


class LogStatistics:
    """
    Counts things in your logs
    
    Like counting words in an essay
    """
    
    def __init__(self, lines):
        self.lines = lines
    
    def get_stats(self):
        """Calculate basic numbers"""
        
        total_lines = len(self.lines)
        total_chars = sum(len(line) for line in self.lines)
        
        # Find longest and shortest lines
        line_lengths = [len(line.strip()) for line in self.lines if line.strip()]
        
        return {
            'total_lines': total_lines,
            'total_chars': total_chars,
            'avg_length': total_chars // total_lines if total_lines > 0 else 0,
            'longest': max(line_lengths) if line_lengths else 0,
            'shortest': min(line_lengths) if line_lengths else 0
        }
    
    def print_stats(self):
        """Show the statistics nicely"""
        
        stats = self.get_stats()
        
        print("\n" + "="*80)
        print("LOG FILE STATISTICS")
        print("="*80)
        print(f"  Total Lines:     {stats['total_lines']}")
        print(f"  Total Characters: {stats['total_chars']:,}")
        print(f"  Average Length:  {stats['avg_length']} characters")
        print(f"  Longest Line:    {stats['longest']} characters")
        print(f"  Shortest Line:   {stats['shortest']} characters")
        print("="*80 + "\n")


# TEST THE CODE
if __name__ == "__main__":
    print("🟦 PROJECT 1 - DAY 2: Understanding Log Format\n")
    
    # Sample log line to analyze
    sample = "Jan 19 10:23:15 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"
    
    # Break it down
    analyze_log_line(sample)
    
    # Show patterns
    show_log_patterns()
    
    # If you have the auth.log file, analyze it
    try:
        with open("../../data/sample_logs/auth.log", 'r') as f:
            lines = f.readlines()
        
        stats = LogStatistics(lines)
        stats.print_stats()
        
        print("✅ Day 2 Complete! You understand log structure now!")
        
    except FileNotFoundError:
        print("⚠️  Run this from the right directory to see full stats")
