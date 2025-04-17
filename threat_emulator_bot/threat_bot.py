import json
import random
import subprocess
import argparse
import platform
import os
import datetime
from pathlib import Path
from datetime import datetime

EXECUTION_LOG_JSON = "execution_log.json"

def log_structured_event(event_data):
    if not os.path.exists(EXECUTION_LOG_JSON):
        with open(EXECUTION_LOG_JSON, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)
    with open(EXECUTION_LOG_JSON, 'r+', encoding='utf-8') as f:
        data = json.load(f)
        data.append(event_data)
        f.seek(0)
        json.dump(data, f, indent=2)
        f.truncate()

LOG_DIR = "logs"

def load_ttps(file_path='ttp_library.json'):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Failed to load TTP set: {e}")
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
    os_name = platform.system()
    hostname = platform.node()
    arch = platform.machine()
    version = platform.version()
    print(f"""
🖥️  OS Detected: {os_name}
🔹 Hostname: {hostname}
🔹 Architecture: {arch}
🔹 Version: {version}
""")
    return f"OS: {os_name}, Host: {hostname}, Arch: {arch}, Ver: {version}"

def execute_ttp(ttp, dry_run=False, logfile="threat_log.json", attack_map=None):
    command = ttp["command"]
    tactic = ttp.get("tactic", "Unknown")
    technique = ttp.get("technique", "Unknown")
    result = None

    print(f"\n🔥 Executing: {ttp['name']}")
    print(f"📝 {ttp['description']}")
    print(f"💻 Command: {command}")
    print(f"\n🎯 MITRE Tactic: {tactic}")
    print(f"🔍 Technique: {technique}")
    if ttp.get("url"):
        print(f"📚 Details: {ttp['url']}")

    if not dry_run:
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ttp_id": ttp["id"],
            "name": ttp["name"],
            "description": ttp["description"],
            "command": command,
            "output": result.stdout,
            "error": result.stderr
        }
    else:
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ttp_id": ttp["id"],
            "name": ttp["name"],
            "description": ttp["description"],
            "command": command,
            "output": None,
            "error": None
        }

    # Append log to file
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

def is_compatible(ttp, current_os):
    return ttp['platform'] == 'all' or ttp['platform'] == current_os

def main(dry_run=False, iterations=3, ttp_set='ttp_library.json'):
    attack_map = load_attack_mapping() # Always load MITRE map for potential enrichment
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    Path(LOG_DIR).mkdir(exist_ok=True)
    logfile = os.path.join(LOG_DIR, f"threat_bot_{timestamp}.log")

    banner_info = os_banner()
    log_to_file(logfile, f"Threat Emulation Started at {timestamp}\n{banner_info}")
    current_os = platform.system().lower()

    final_summary = ""

    if ttp_set == 'attack-dataset.json':
        print(f"\n⚙️ Running in MITRE ATT&CK mode using '{ttp_set}' for technique selection.")
        log_to_file(logfile, f"Running in MITRE ATT&CK mode using '{ttp_set}'.")
        iterations = 5 

        # Load command library separately
        command_library = load_ttps('ttp_library.json')
        if not command_library:
             msg = "❌ Cannot run MITRE mode: Failed to load command library 'ttp_library.json'."
             print(msg)
             log_to_file(logfile, msg)
             return

        # Get all available MITRE technique IDs from the map
        mitre_ids = list(attack_map.keys())
        if not mitre_ids:
            msg = "❌ Cannot run MITRE mode: Failed to load any techniques from 'attack-dataset.json'."
            print(msg)
            log_to_file(logfile, msg)
            return

        # Create a lookup for commands by ID for faster access
        commands_by_id = {ttp['id']: ttp for ttp in command_library}

        # Select 5 random MITRE IDs, ensure we don't select more than available
        actual_iterations = min(iterations, len(mitre_ids))
        if actual_iterations < iterations:
             print(f"⚠️ Warning: Only {actual_iterations} MITRE techniques available, selecting all.")
        selected_mitre_ids = random.sample(mitre_ids, actual_iterations)

        summary = f"🎯 Selected {len(selected_mitre_ids)} random MITRE Techniques (Dry run: {dry_run})\n"
        print(summary)
        log_to_file(logfile, summary)

        executed_count = 0
        for technique_id in selected_mitre_ids:
            mitre_info = attack_map.get(technique_id)
            command_ttp = commands_by_id.get(technique_id)

            print(f"\n--- Technique: {technique_id} ---")
            log_entry_prefix = f"Attempting MITRE Technique: {technique_id}"
            if mitre_info:
                print(f"📄 Name: {mitre_info.get('name', 'N/A')}")
                # print(f"ℹ️ Description: {mitre_info.get('description', 'N/A')[:150]}...") # Optional: Shorten desc
                print(f"⚔️ Tactic: {mitre_info.get('tactic', 'N/A')}")
                if mitre_info.get('url'):
                    print(f"🔗 URL: {mitre_info['url']}")
                log_entry_prefix += f" ({mitre_info.get('name', 'N/A')})"

            if command_ttp:
                print(f"💻 Associated Command Found in ttp_library.json: {command_ttp.get('name', technique_id)}")
                if is_compatible(command_ttp, current_os):
                    print(f"✅ Compatible with {current_os.upper()}. Preparing execution...")
                    log_to_file(logfile, f"{log_entry_prefix} - Found compatible command: {command_ttp.get('name', technique_id)}")
                    # Pass the command TTP (from ttp_library) to execute_ttp
                    execute_ttp(command_ttp, dry_run=dry_run, logfile=logfile, attack_map=attack_map)
                    executed_count += 1
                else:
                    msg = f"⚠️ Not compatible with current OS ({current_os.upper()}). Skipping execution."
                    print(msg)
                    log_to_file(logfile, f"{log_entry_prefix} - {msg} (Command Platform: {command_ttp.get('platform')})" )
            else:
                msg = f"❌ No executable command found for {technique_id} in 'ttp_library.json'. Cannot execute."
                print(msg)
                log_to_file(logfile, f"{log_entry_prefix} - {msg}")

        final_summary = f"✅ MITRE Mode: Attempted {len(selected_mitre_ids)} techniques, Executed {executed_count} compatible commands."

    else: # Original logic for ttp_library.json or other custom sets
        print(f"\n⚙️ Running in Standard TTP mode using '{ttp_set}'.")
        log_to_file(logfile, f"Running in Standard TTP mode using '{ttp_set}'.")
        all_ttps = load_ttps(ttp_set)
        if not all_ttps:
             msg = f"❌ Failed to load TTPs from '{ttp_set}'."
             print(msg)
             log_to_file(logfile, msg)
             return

        compatible_ttps = [t for t in all_ttps if is_compatible(t, current_os)]

        if not compatible_ttps:
            msg = f"❌ No compatible TTPs found for this OS in '{ttp_set}'."
            print(msg)
            log_to_file(logfile, msg)
            return

        # Ensure we don't try to select more than available
        actual_iterations = min(iterations, len(compatible_ttps))
        if actual_iterations < iterations:
             print(f"⚠️ Warning: Only {actual_iterations} compatible TTPs available in '{ttp_set}', selecting all.")

        summary = f"🎯 Selected {actual_iterations} random TTPs from '{ttp_set}' (Dry run: {dry_run})\n"
        print(summary)
        log_to_file(logfile, summary)

        executed_count = 0
        selected_ttps = random.sample(compatible_ttps, actual_iterations)

        for ttp in selected_ttps:
            execute_ttp(ttp, dry_run=dry_run, logfile=logfile, attack_map=attack_map)
            executed_count += 1

        final_summary = f"✅ Standard Mode: Executed {executed_count} TTPs from '{ttp_set}' ({actual_iterations} selected)."

    print(f"\n{final_summary}")
    print(f"📁 Log saved to {logfile}")
    log_to_file(logfile, f"\n{final_summary}")
    log_to_file(logfile, f"✅ Emulation complete at {datetime.now()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Emulation Bot")
    parser.add_argument("--dry-run", action="store_true", help="Only print commands, do not execute")
    parser.add_argument("--iterations", type=int, default=3, help="Number of random TTPs to run")
    parser.add_argument("--ttp-set", type=str, default="ttp_library.json", help="Path to custom TTP JSON set")
    args = parser.parse_args()

    main(dry_run=args.dry_run, iterations=args.iterations, ttp_set=args.ttp_set)

