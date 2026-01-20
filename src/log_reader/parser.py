"""
Log Parser - Day 1: Basic File Reading
Read log files and print each line
"""

class LogReader:
    """Simple log file reader"""
    
    def __init__(self, log_file_path):
        """
        Initialize log reader
        
        Args:
            log_file_path (str): Path to the log file
        """
        self.log_file_path = log_file_path
        self.lines = []
    
    def read_logs(self):
        """
        Read all lines from the log file
        
        Returns:
            list: List of log lines
        """
        try:
            with open(self.log_file_path, 'r') as file:
                self.lines = file.readlines()
            print(f"✅ Successfully read {len(self.lines)} lines from {self.log_file_path}")
            return self.lines
        except FileNotFoundError:
            print(f"❌ Error: File not found - {self.log_file_path}")
            return []
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            return []
    
    def print_logs(self):
        """Print each log line with line numbers"""
        if not self.lines:
            print("⚠️  No logs to display. Run read_logs() first.")
            return
        
        print("\n" + "="*80)
        print("📋 LOG FILE CONTENTS")
        print("="*80 + "\n")
        
        for i, line in enumerate(self.lines, 1):
            print(f"{i:3d} | {line.strip()}")
        
        print("\n" + "="*80)
        print(f"Total lines: {len(self.lines)}")
        print("="*80 + "\n")


def main():
    """Main function to demonstrate log reading"""
    print("🚀 Day 1: Basic Log Reader\n")
    
    # Create log reader instance
    log_path = "data/sample_logs/auth.log"
    reader = LogReader(log_path)
    
    # Read and display logs
    reader.read_logs()
    reader.print_logs()


if __name__ == "__main__":
    main()
