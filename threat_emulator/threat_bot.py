import json
import random
import subprocess
import argparse
import platform as plat
import os
import datetime
from pathlib import Path
from datetime import datetime

EXECUTION_LOG_JSON = "execution_log.json"
ATTACK_DATASET_FILE = "attack_dataset.json" # Define constant for the filename

# Function to log structured event data to a JSON file
# Reads the whole file, appends, and writes back to ensure valid JSON list format
def log_structured_event(event_data):
    data = []
    try:
        # Try to read existing data if file exists and is not empty
        if os.path.exists(EXECUTION_LOG_JSON) and os.path.getsize(EXECUTION_LOG_JSON) > 0:
            with open(EXECUTION_LOG_JSON, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    if not isinstance(data, list): # Ensure it's a list
                       print(f"⚠️ Warning: {EXECUTION_LOG_JSON} does not contain a JSON list. Resetting.")
                       data = []
                except json.JSONDecodeError:
                    # Handle case where file is corrupted or not valid JSON
                    print(f"⚠️ Warning: Could not decode JSON from {EXECUTION_LOG_JSON}. Resetting.")
                    data = [] # Start fresh if file is corrupt
        
        # Append the new event
        data.append(event_data)

        # Write the entire list back
        # Ensure the logs directory exists first (should normally exist, but good practice)
        Path(LOG_DIR).mkdir(exist_ok=True) 
        with open(EXECUTION_LOG_JSON, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2) # Use indent for readability

    except Exception as e:
        print(f"❌ Error logging structured event to {EXECUTION_LOG_JSON}: {e}")

LOG_DIR = "logs"

# Function to load TTPs from a JSON file
# Updated to handle different TTP library formats
def load_ttps(filepath):
    """Loads TTP definitions from a JSON file, handling different formats."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Handle specific structure of MITRE ATT&CK dataset
            # Use the constant ATTACK_DATASET_FILE defined earlier
            if filepath == ATTACK_DATASET_FILE: 
                if isinstance(data, dict) and isinstance(data.get("objects"), list):
                    # Filter for attack-patterns only
                    return [obj for obj in data["objects"] if obj.get("type") == "attack-pattern"]
                else:
                    print(f"❌ Error: Unexpected format in {ATTACK_DATASET_FILE}. Expected dict with 'objects' list.")
                    return []
            # Assume other files contain a list of TTPs directly
            elif isinstance(data, list):
                return data
            else:
                 print(f"❌ Error: Unexpected format in {filepath}. Expected a JSON list.")
                 return []
    except FileNotFoundError:
        # Use print for console output in the bot script
        print(f"❌ Error: TTP file not found at {filepath}") 
        return []
    except json.JSONDecodeError:
        print(f"❌ Error: Could not decode JSON from {filepath}")
        return []
    except Exception as e:
        print(f"❌ An unexpected error occurred loading {filepath}: {e}")
        return []

def load_attack_mapping(dataset='attack_dataset.json'):
    try:
        with open(dataset, 'r', encoding='utf-8') as f:
            data = json.load(f)

        id_to_technique = {}
        for obj in data['objects']:
            if obj.get('type') == 'attack-pattern' and 'external_references' in obj:
                for ref in obj['external_references']:
                    if ref.get('source_name') == 'mitre-attack' and 'external_id' in ref:
                        ext_id = ref['external_id']
                        id_to_technique[ext_id] = {
                            'name': obj.get('name'),
                            'description': obj.get('description', ''),
                            'tactic': obj.get('kill_chain_phases', [{}])[0].get('phase_name', 'unknown'),
                            'url': ref.get('url', '')
                        }
        return id_to_technique

    except Exception as e:
        print(f"❌ Failed to load MITRE ATT&CK mapping: {e}")
        return {}

def log_to_file(logfile, text):
    with open(logfile, 'a', encoding='utf-8') as f:
        f.write(text + '\n')

def os_banner():
    os_name = plat.system()
    hostname = plat.node()
    arch = plat.machine()
    version = plat.version()
    print(f"""
🖥️  OS Detected: {os_name}
🔹 Hostname: {hostname}
🔹 Architecture: {arch}
🔹 Version: {version}
""")
    return f"OS: {os_name}, Host: {hostname}, Arch: {arch}, Ver: {version}"

#the logfile will change because logfile=logfile inside main
def execute_ttp(ttp, dry_run=False, logfile="threat_log.json", attack_map=None, base_log_filename=None, execution_log_path=None): 
    ttp_id = ttp.get("id", "N/A")
    ttp_name = ttp.get("name", "Unknown TTP")
    command = ttp.get("command", "")
    ttp_platform = ttp.get("platform", "N/A")
    current_os = plat.system().lower()
    log_entry_prefix = f"[{datetime.now().isoformat()}] TTP: {ttp_id} ({ttp_name})"

    print(f"\n{'='*10} Executing TTP: {ttp_id} - {ttp_name} {'='*10}")
    print(f"Command: {command}")
    print(f"Platform: {ttp_platform}")
    print(f"Dry Run: {dry_run}")
    log_to_file(logfile, f"{log_entry_prefix} - Command: {command}")
    log_to_file(logfile, f"{log_entry_prefix} - Platform: {ttp_platform}")
    log_to_file(logfile, f"{log_entry_prefix} - Dry Run: {dry_run}")

    if ttp_platform != 'all' and ttp_platform != current_os:
        msg = f"Skipping TTP {ttp_id}: Platform mismatch (requires '{ttp_platform}', host is '{current_os}')"
        print(f"⚠️ {msg}")
        log_to_file(logfile, f"{log_entry_prefix} - {msg}")
        log_structured_event({
            "timestamp": datetime.now().isoformat(),
            "status": "Skipped (Platform)",
            "id": ttp_id,
            "name": ttp_name,
            "command": command,
            "dry_run": dry_run,
            "platform": ttp_platform,
            "output": None,
            "error": None,
            "exit_code": None,
            "mitre_tactic": ttp.get("mitre_tactic", "N/A"),
            "mitre_technique": ttp.get("mitre_technique", "N/A")
        })
        print("-" * 30)
        return True # Skipped is not a failure

    if not command:
        msg = f"Skipping TTP {ttp_id}: No command defined."
        print(f"⚠️ {msg}")
        log_to_file(logfile, f"{log_entry_prefix} - {msg}")
        log_structured_event({
            "timestamp": datetime.now().isoformat(),
            "status": "Skipped (No Command)",
            "id": ttp_id,
            "name": ttp_name,
            "command": command,
            "dry_run": dry_run,
            "platform": ttp_platform,
            "output": None,
            "error": None,
            "exit_code": None,
            "mitre_tactic": ttp.get("mitre_tactic", "N/A"),
            "mitre_technique": ttp.get("mitre_technique", "N/A")
        })
        print("-" * 30)
        return True # Skipped is not a failure

    stdout_content = None # Initialize
    stderr_content = None # Initialize
    execution_status = "Unknown" # Initialize
    result = None # Initialize

    if not dry_run:
        print(f"⚡ Executing... (~60s timeout)")
        log_to_file(logfile, f"{log_entry_prefix} - Executing...")
        try:
            # Execute command with timeout, explicit encoding, and error handling
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                shell=True,
                timeout=60,
                encoding='utf-8', # Specify encoding
                errors='ignore'   # Ignore decoding errors
            )
            log_to_file(logfile, f"{log_entry_prefix} - Exit Code: {result.returncode}") # Log exit code first

            # Log stdout if it exists
            if result.stdout:
                stdout_content = result.stdout.strip()
                if stdout_content: # Ensure stripped content is not empty
                    log_to_file(logfile, f"{log_entry_prefix} - Stdout:\n--- Start STDOUT ---\n{stdout_content}\n--- End STDOUT ---")
            
            # Log stderr if it exists
            if result.stderr:
                stderr_content = result.stderr.strip()
                if stderr_content: # Ensure stripped content is not empty
                    log_to_file(logfile, f"{log_entry_prefix} - Stderr:\n--- Start STDERR ---\n{stderr_content}\n--- End STDERR ---")

            # Determine final status based ONLY on return code
            if result.returncode == 0:
                execution_status = "Success"
                print(f"   -> Status: ✅ {execution_status}") # Print simple status
            else:
                execution_status = f"Failed (Code: {result.returncode})"
                print(f"   -> Status: ❌ {execution_status}") # Print simple status
                # Optionally print stderr snippet to console only on failure
                if stderr_content:
                    print(f"      Stderr: {stderr_content[:200]}{'...' if len(stderr_content) > 200 else ''}")
            
            log_to_file(logfile, f"{log_entry_prefix} - Status: {execution_status}")

        except subprocess.TimeoutExpired:
            execution_status = "Failed (Timeout)"
            error_msg = f"{log_entry_prefix} - Error: Command timed out after 60 seconds."
            print(f"   -> Status: ❌ {execution_status}")
            log_to_file(logfile, error_msg)
            log_to_file(logfile, f"{log_entry_prefix} - Status: {execution_status}") # Log status on timeout too
            stderr_content = "TimeoutExpired" # For structured log

        except Exception as e:
            execution_status = "Failed (Exception)"
            error_msg = f"{log_entry_prefix} - Error: Exception during execution: {str(e)}"
            print(f"   -> Status: ❌ {execution_status}")
            log_to_file(logfile, error_msg)
            log_to_file(logfile, f"{log_entry_prefix} - Status: {execution_status}") # Log status on exception too
            stderr_content = str(e) # For structured log
            result = None # No result object available here

    else: # Dry Run
        print("💨 Dry Run: Command not executed.")
        log_to_file(logfile, f"{log_entry_prefix} - Dry Run: Command not executed.")
        execution_status = "DryRun"

    # --- Demo Log Generation ---
    if base_log_filename and 'expected_logs' in ttp:
        print("📄 Generating demo logs...")
        log_to_file(logfile, f"{log_entry_prefix} - Generating demo logs.")
        for tool, log_lines in ttp['expected_logs'].items():
            if log_lines: # Only create/log if there are expected lines for the tool
                demo_log_path = os.path.join(LOG_DIR, f"{base_log_filename}.{tool}.log")
                log_to_file(logfile, f"{log_entry_prefix} - Writing {len(log_lines)} lines to {demo_log_path}")
                try:
                    # Ensure the logs directory exists (should be created by main, but safe to double-check)
                    Path(LOG_DIR).mkdir(exist_ok=True)
                    with open(demo_log_path, 'a', encoding='utf-8') as demo_f:
                        for line in log_lines:
                            # Add a timestamp prefix to make demo logs slightly more dynamic
                            timestamped_line = f"[{datetime.now().isoformat()}] {line}"
                            demo_f.write(timestamped_line + '\n')
                    print(f"   -> Demo logs written to {os.path.basename(demo_log_path)}")
                except Exception as e:
                    error_msg = f"Failed to write demo log {demo_log_path}: {e}"
                    print(f"   ❌ Error: {error_msg}")
                    log_to_file(logfile, f"{log_entry_prefix} - Error: {error_msg}")

    # --- Structured Logging ---
    log_structured_event({
        "timestamp": datetime.now().isoformat(),
        "status": execution_status,
        "id": ttp.get("id", "N/A"),
        "name": ttp.get("name", "N/A"),
        "command": command,
        "dry_run": dry_run,
        "platform": ttp_platform,
        "output": stdout_content if execution_status == "Success" else None,
        "error": stderr_content if execution_status not in ["Success", "DryRun"] else None,
        "exit_code": result.returncode if result else None,
        "mitre_tactic": ttp.get("mitre_tactic", "N/A"),
        "mitre_technique": ttp.get("mitre_technique", "N/A")
    })

    print("-" * 30) # Separator in console output

    return execution_status in ["Success", "DryRun"] # Return True for Success or DryRun


# Check TTP compatibility with the current OS
# Updated to check MITRE's 'x_mitre_platforms' if 'platform' is missing
def is_compatible(ttp, current_os):
    """Checks if a TTP is compatible with the current OS."""
    # Check standard 'platform' key first
    platform_info = ttp.get('platform') 
    
    # If standard key missing, check MITRE's 'x_mitre_platforms'
    if platform_info is None: 
        platform_info = ttp.get('x_mitre_platforms')

    # If still no platform info, assume incompatible or handle as 'all'? 
    # For now, let's be strict: requires platform info.
    if platform_info is None:
        # Optional: Print a warning if needed for debugging
        # print(f"❓ Warning: No platform info found for TTP {ttp.get('id', ttp.get('name', 'Unknown'))}. Assuming incompatible.")
        return False

    # Normalize to list if it's a string
    if isinstance(platform_info, str):
        platforms = [platform_info.lower()]
    elif isinstance(platform_info, list):
        # Ensure all elements in the list are strings before lowercasing
        platforms = [p.lower() for p in platform_info if isinstance(p, str)]
    else:
         # Optional: Print a warning for unexpected format
         # print(f"❓ Warning: Unexpected platform format for TTP {ttp.get('id', ttp.get('name', 'Unknown'))}: {platform_info}. Assuming incompatible.")
         return False # Unexpected format

    # Check for 'all' compatibility first
    if 'all' in platforms:
        return True
        
    # Map common OS names for broader compatibility (e.g., 'windows' should match 'windows')
    # MITRE uses: Linux, macOS, Windows, Azure AD, Office 365, SaaS, IaaS, Google Workspace, PRE, Network, Containers
    os_mapping = {
        'windows': 'windows',
        'linux': 'linux',
        'darwin': 'macos' # Map macOS from plat.system() to MITRE's term
        # Add other mappings if needed (e.g., 'freebsd': 'linux' if desired)
    }
    mapped_os = os_mapping.get(current_os) 

    # Check if the mapped OS is directly listed in the platforms
    if mapped_os and mapped_os in platforms:
        return True
        
    # Optional: Add checks for broader categories based on the mapped OS
    # Example: If running on Linux, also allow TTPs marked 'Network' or 'Containers'?
    # if mapped_os == 'linux' and ('network' in platforms or 'containers' in platforms):
    #     return True
        
    return False # Not compatible if no specific or broad match found

# The core execution logic, now accepting the parsed arguments object
def main(args):
    attack_map = load_attack_mapping() # Load MITRE mapping if needed
    current_os = plat.system().lower()

    # --- Setup Logging ---
    # Use args.log_dir from the parsed arguments
    Path(args.log_dir).mkdir(parents=True, exist_ok=True) 
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_log_filename = os.path.join(args.log_dir, f"threat_bot_{timestamp}")
    log_filename = f"{base_log_filename}.log" # Main execution log
    # Construct execution log path relative to log_dir
    execution_log_path = os.path.join(args.log_dir, EXECUTION_LOG_JSON) 

    print(f"📝 Logging execution details to: {log_filename}")
    print(f"📊 Structured execution log: {execution_log_path}")

    # --- Execution Logic ---
    ttps_to_run = []

    # Use args.ttp_set, args.scenario_file, args.base_library etc. from here on
    if args.ttp_set.startswith("scenario:"):
        scenario_name = args.ttp_set.split(":", 1)[1]
        print(f"🚀 Running Scenario: {scenario_name}")
        # Load the scenario definitions
        try:
            # Use args.scenario_file
            with open(args.scenario_file, 'r', encoding='utf-8') as f:
                all_scenarios = json.load(f)
            scenario_ttp_ids = all_scenarios.get(scenario_name)
            if not scenario_ttp_ids:
                print(f"❌ Error: Scenario '{scenario_name}' not found in {args.scenario_file}")
                exit(1) # Exit if scenario not found
            if not isinstance(scenario_ttp_ids, list):
                 print(f"❌ Error: Scenario '{scenario_name}' in {args.scenario_file} is not a list of TTP IDs.")
                 exit(1)

        except FileNotFoundError:
            print(f"❌ Error: Scenario file '{args.scenario_file}' not found.")
            exit(1)
        except json.JSONDecodeError:
            print(f"❌ Error: Could not decode JSON from scenario file '{args.scenario_file}'.")
            exit(1)
        except Exception as e:
            print(f"❌ Error loading scenario file '{args.scenario_file}': {e}")
            exit(1)
            
        # Load the base TTP library to get full definitions
        # Use args.base_library
        print(f"📖 Loading base TTP definitions from: {args.base_library}")
        base_ttps = load_ttps(args.base_library)
        if not base_ttps:
            print(f"❌ Error: Could not load base TTP library from '{args.base_library}'. Cannot execute scenario.")
            exit(1)
            
        ttp_dict = {ttp['id']: ttp for ttp in base_ttps}
        print(f"📋 Scenario Steps (TTP IDs): {', '.join(scenario_ttp_ids)}")
        for ttp_id in scenario_ttp_ids:
            ttp = ttp_dict.get(ttp_id)
            if ttp:
                if is_compatible(ttp, current_os):
                    ttps_to_run.append(ttp)
                else:
                    # Use args.base_library in warning message
                    warning_msg = f"⚠️ Warning: TTP ID '{ttp_id}' ({ttp.get('name', 'N/A')}) from scenario '{scenario_name}' is not compatible with the current OS ({current_os}). Skipping step."
                    print(warning_msg)
                    log_to_file(log_filename, warning_msg) # Use log_filename
            else:
                 # Use args.base_library in warning message
                warning_msg = f"⚠️ Warning: TTP ID '{ttp_id}' from scenario '{scenario_name}' not found in base library '{args.base_library}'. Skipping step."
                print(warning_msg)
                log_to_file(log_filename, warning_msg) # Use log_filename
                
        print(f"ℹ️ Running {len(ttps_to_run)} compatible steps from the scenario.")

    else:
        # Standard execution: Load TTPs from the specified file (args.ttp_set)
        print(f"📖 Loading TTPs from: {args.ttp_set}")
        all_ttps = load_ttps(args.ttp_set)
        if not all_ttps:
             print(f"❌ No TTPs loaded from '{args.ttp_set}'. Exiting.")
             exit(1)

        compatible_ttps = [t for t in all_ttps if is_compatible(t, current_os)]
        print(f"✅ Found {len(compatible_ttps)} TTPs compatible with {current_os} (out of {len(all_ttps)} total).")
        
        if not compatible_ttps:
             print(f"❌ No compatible TTPs found for the current OS ({current_os}) in '{args.ttp_set}'. Exiting.")
             exit(1)

        # Select random TTPs based on args.iterations
        num_to_run = min(args.iterations, len(compatible_ttps))
        print(f"🎲 Selecting {num_to_run} random TTPs to run (using --iterations)..." if num_to_run > 0 else "🚫 No compatible TTPs to select randomly.")
        if num_to_run > 0:
            ttps_to_run = random.sample(compatible_ttps, num_to_run)
        else:
            ttps_to_run = [] 


    # --- Execute Selected TTPs ---
    if not ttps_to_run:
        print("🚫 No TTPs selected or found to execute.")
    else:
        print(f"\n--- Starting Threat Emulation ({len(ttps_to_run)} TTPs) ---")
        for i, ttp in enumerate(ttps_to_run):
            print(f"\n--- Executing Step {i+1}/{len(ttps_to_run)}: {ttp.get('id')} - {ttp.get('name')} ---")
            # Pass args.dry_run directly from the parsed arguments
            execute_ttp(ttp, args.dry_run, log_filename, attack_map, base_log_filename, execution_log_path) 

    print("\n--- Threat Emulation Finished ---")


# Main execution block - Now only parses args and calls main()
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Emulator Bot")
    parser.add_argument("--ttp-set", default="ttp_library.json",
                        help="Path to TTP library JSON file OR scenario identifier (e.g., 'scenario:My Scenario')")
    parser.add_argument("--iterations", type=int, default=1, # Default iterations used if not a scenario
                        help="Number of TTPs to execute randomly (ignored if a scenario is selected)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print commands instead of executing them")
    parser.add_argument("--log-dir", default=LOG_DIR, help="Directory for log files")
    parser.add_argument("--base-library", default="ttp_library.json", 
                        help="Base TTP library used to look up TTP definitions for scenarios")
    parser.add_argument("--scenario-file", default="attack_scenarios.json", 
                        help="Path to the attack scenario definition file")

    args = parser.parse_args()
    
    # Call the main execution logic function with the parsed arguments
    main(args)
