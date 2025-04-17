import os
import json
import glob
from collections import Counter
from datetime import datetime, date
import argparse

LOG_DIR = "logs"
LOG_PREFIX = "threat_bot_"

def analyze_logs(target_date: date):
    """Analyzes threat bot logs for a specific date."""
    log_pattern = os.path.join(LOG_DIR, f"{LOG_PREFIX}{target_date.strftime('%Y%m%d')}_*.log")
    log_files = glob.glob(log_pattern)

    if not log_files:
        print(f"No log files found for {target_date.strftime('%Y-%m-%d')} in '{LOG_DIR}'.")
        return

    print(f"--- Daily Analysis for {target_date.strftime('%Y-%m-%d')} ---")
    print(f"Found {len(log_files)} log file(s): {', '.join(os.path.basename(f) for f in log_files)}\n")

    total_runs = 0
    ttp_attempts = []
    skipped_incompatible = 0
    skipped_no_command = 0
    execution_errors = 0

    for log_file in log_files:
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Check for run start marker
                    if "Threat Emulation Started at" in line:
                        total_runs += 1
                        continue

                    # Check for plain text skip messages
                    if "Not compatible with current OS" in line:
                        skipped_incompatible += 1
                        continue
                    if "No executable command found for" in line and "in 'ttp_library.json'" in line:
                        skipped_no_command += 1
                        continue

                    # Try parsing as JSON (TTP execution log)
                    try:
                        log_entry = json.loads(line)
                        if isinstance(log_entry, dict) and 'ttp_id' in log_entry:
                            ttp_attempts.append(log_entry['ttp_id'])
                            # Check if the command execution itself produced an error stream
                            if log_entry.get('error') and log_entry['error'].strip():
                                execution_errors += 1
                    except json.JSONDecodeError:
                        # Ignore lines that are not JSON (likely plain text status messages)
                        pass
        except Exception as e:
            print(f"Error reading or processing file {os.path.basename(log_file)}: {e}")

    # --- Generate Summary --- #
    print(f"Total Emulation Runs Started: {total_runs}")
    print(f"Total TTPs Attempted: {len(ttp_attempts)}")

    if ttp_attempts:
        ttp_counts = Counter(ttp_attempts)
        unique_ttps = len(ttp_counts)
        print(f"Unique TTP IDs Attempted: {unique_ttps}")
        print("\nFrequency per TTP ID:")
        # Sort by count descending for readability
        for ttp_id, count in sorted(ttp_counts.items(), key=lambda item: item[1], reverse=True):
            print(f"  - {ttp_id}: {count} attempt(s)")

    print(f"\nSkipped TTPs (OS Incompatibility): {skipped_incompatible}")
    print(f"Skipped TTPs (Command Not Found in ttp_library.json): {skipped_no_command}")
    print(f"TTP Executions with Errors (stderr): {execution_errors}")
    print("\n--- End of Analysis ---")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Threat Emulation Bot logs for a specific day.")
    parser.add_argument(
        "-d", "--date",
        type=str,
        help="Date to analyze in YYYY-MM-DD format. Defaults to today."
    )
    args = parser.parse_args()

    analysis_date = date.today()
    if args.date:
        try:
            analysis_date = datetime.strptime(args.date, '%Y-%m-%d').date()
        except ValueError:
            print("Error: Date must be in YYYY-MM-DD format.")
            exit(1)

    analyze_logs(analysis_date)
