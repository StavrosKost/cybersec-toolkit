import os
import subprocess
import glob
import time
import streamlit as st
import json
from utils import load_attack_mapping

# Constants
TTP_LIBRARY_FILE = "ttp_library.json"
ATTACK_DATASET_FILE = "attack_dataset.json"
SCENARIO_FILE = "attack_scenarios.json"
LOG_DIR = "logs"
EXECUTION_LOG_JSON = "execution_log.json"

# --- Helper Functions ---

# Function to load TTPs from a JSON file
def load_ttps(filepath):
    """Loads TTP definitions from a JSON file, handling different formats."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Handle specific structure of MITRE ATT&CK dataset
            if filepath == ATTACK_DATASET_FILE:
                 # Ensure it's a dict and has 'objects' key which is a list
                if isinstance(data, dict) and isinstance(data.get("objects"), list):
                    # Filter for attack-patterns only, as the dataset contains other object types
                    return [obj for obj in data["objects"] if obj.get("type") == "attack-pattern"]
                else:
                    st.error(f"Error: Unexpected format in {ATTACK_DATASET_FILE}. Expected a dict with an 'objects' list.")
                    return []
            # Assume other files contain a list of TTPs directly
            elif isinstance(data, list):
                return data
            else:
                 st.error(f"Error: Unexpected format in {filepath}. Expected a JSON list.")
                 return []
    except FileNotFoundError:
        st.error(f"Error: TTP file not found at {filepath}")
        return []
    except json.JSONDecodeError:
        st.error(f"Error: Could not decode JSON from {filepath}")
        return []
    except Exception as e:
        st.error(f"An unexpected error occurred loading {filepath}: {e}")
        return []

def load_executions(filepath=EXECUTION_LOG_JSON):
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        st.error(f"Error: Could not decode execution log {filepath}. It might be corrupted.")
        return []
    except Exception as e:
        st.error(f"An error occurred loading execution log: {e}")
        return []

def load_scenario_names(filepath=SCENARIO_FILE):
    scenario_names = []
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                scenarios = json.load(f)
                if isinstance(scenarios, dict):
                    scenario_names = list(scenarios.keys())
                else:
                    st.sidebar.warning(f"{filepath} is not a valid scenario format (expected dictionary).")
        except json.JSONDecodeError:
            st.sidebar.error(f"Error decoding {filepath}. Ensure it's valid JSON.")
        except Exception as e:
            st.sidebar.error(f"Error loading scenarios from {filepath}: {e}")
    else:
        pass
    return scenario_names

# --- Dashboard UI ---
st.set_page_config(page_title="Threat Emulation Dashboard", layout="wide")
st.title("🚨 Threat Emulation Live Dashboard")

# --- Sidebar ---
st.sidebar.header("⚙️ Emulation Control")

ttp_options = [TTP_LIBRARY_FILE, ATTACK_DATASET_FILE]
scenario_names = load_scenario_names()
scenario_options = [f"scenario:{name}" for name in scenario_names]

all_options = ttp_options + scenario_options
display_options = {
    TTP_LIBRARY_FILE: "Standard TTP Library",
    ATTACK_DATASET_FILE: "MITRE ATT&CK Dataset (All)",
    **{f"scenario:{name}": f"Scenario: {name}" for name in scenario_names}
}

selected_option = st.sidebar.selectbox(
    "Select TTP Set or Scenario:",
    options=all_options,
    format_func=lambda x: display_options.get(x, x),
    help="Choose a TTP library (run random TTPs or all MITRE) or a predefined Scenario (run specific TTPs in order)."
)

is_scenario = "scenario:" in selected_option
iterations = st.sidebar.slider(
    "Number of TTPs to Run (if applicable):",
    min_value=1,
    max_value=20,
    value=3,
    disabled=is_scenario or selected_option == ATTACK_DATASET_FILE,
    help="Only used when a TTP library is selected. Determines how many random TTPs are run."
)
dry_run = st.sidebar.checkbox("Dry Run Mode", value=True)

# --- Execution Control ---
st.markdown("---")
st.header("🚀 Execute")

# Determine if the run button should be disabled
# Disable if MITRE dataset is selected (as it's non-executable) AND it's not a scenario run
disable_run_button = False
if not is_scenario and selected_option == ATTACK_DATASET_FILE:
    disable_run_button = True
    st.info("ℹ️ The full MITRE ATT&CK dataset is for reference only and does not contain executable commands. Running the bot is disabled for this selection.")
elif not selected_option: # Also disable if nothing is selected
     disable_run_button = True
     st.caption("Select a TTP Library or Scenario to enable execution.")

# Add Dry Run checkbox
dry_run = st.checkbox("🌵 Dry Run (Print commands instead of executing)", value=True)

# Button to run the script, now conditionally disabled
if st.button("▶️ Run threat_bot.py", disabled=disable_run_button):
    st.sidebar.info(f"Executing threat_bot.py with {selected_option}...")
    try:
        cmd = ["python", "threat_bot.py", "--ttp-set", selected_option]
        if not is_scenario and selected_option != ATTACK_DATASET_FILE:
            cmd.extend(["--iterations", str(iterations)])
        if dry_run:
            cmd.append("--dry-run")
        subprocess.Popen(cmd)  
        st.sidebar.success("Execution started!")
    except FileNotFoundError:
        st.sidebar.error("Error: 'python' command not found. Is Python installed and in PATH?")
    except Exception as e:
        st.sidebar.error(f"Failed to run: {e}")

# --- Main Area ---

st.header("📄 Selected TTPs / Scenario Steps")

selected_ttps = []
scenario_details = None
current_library_path = None # Keep track of which library was loaded for display logic

if is_scenario: 
    scenario_name = selected_option.split(":", 1)[1]
    st.write(f"Running Scenario: **{scenario_name}**")
    if os.path.exists(SCENARIO_FILE):
         try:
            with open(SCENARIO_FILE, 'r', encoding='utf-8') as f:
                all_scenarios = json.load(f)
                scenario_details = all_scenarios.get(scenario_name)
                if scenario_details:
                     st.write("Steps (TTP IDs):")
                     st.json(scenario_details) 
                     # Note: We don't load the TTP details here, the bot does that
                else:
                     st.error(f"Scenario '{scenario_name}' not found in {SCENARIO_FILE}")
         except Exception as e:
            st.error(f"Error reading scenario file: {e}")
    else:
        st.error(f"{SCENARIO_FILE} not found.")
# Check if the selected option is an existing file (TTP library)
elif os.path.exists(selected_option): 
    current_library_path = selected_option # Store the path
    # Load TTPs if a library file is selected
    st.write(f"Using TTP Library: **{display_options.get(selected_option, selected_option)}** (`{selected_option}`)")
    selected_ttps = load_ttps(selected_option)
    if selected_ttps:
        st.write(f"Loaded {len(selected_ttps)} TTPs from the library.")
        # Optional: Display loaded TTP names/IDs if needed (can be long)
        # with st.expander("View Loaded TTPs"):
        #     st.json([{"id": t.get("id"), "name": t.get("name")} for t in selected_ttps])
    else:
         # This case might happen if the file exists but is empty or invalid JSON
         st.warning(f"Could not load any TTPs from {selected_option}. Check file content and format.")
elif selected_option: # Catch case where option is selected but file doesn't exist
    st.error(f"Selected TTP library file '{selected_option}' not found or not accessible.")
else:
     # Should not happen with selectbox, but good practice
     st.info("Please select a TTP Set or Scenario from the sidebar.")

# Display TTP Details (only if a library was loaded and TTPs exist)
st.subheader("🔍 Browse Loaded TTPs")
if selected_ttps:
    attack_map = load_attack_mapping() # Load mapping once
    
    # Add simple text search for browsing
    search_term = st.text_input("Search loaded TTPs by ID or Name:").lower()
    
    filtered_ttps = []
    if search_term:
        for ttp in selected_ttps:
            # Standardize ID extraction for search
            ttp_id_search = ttp.get('id')
            if not ttp_id_search and current_library_path == ATTACK_DATASET_FILE:
                 ext_refs = ttp.get('external_references', [])
                 for ref in ext_refs:
                     if ref.get('source_name') == 'mitre-attack':
                         ttp_id_search = ref.get('external_id')
                         break
            # Fallback if no ID found after checking ext refs
            ttp_id_search = ttp_id_search or ""
            ttp_name_search = ttp.get('name', '').lower()
            
            if search_term in ttp_id_search.lower() or search_term in ttp_name_search:
                filtered_ttps.append(ttp)
        if not filtered_ttps:
             st.caption("No TTPs match your search term.")
    else:
        filtered_ttps = selected_ttps # Show all if no search term
        
    # Display the filtered TTPs
    for ttp in filtered_ttps:
        ttp_id = ttp.get('id') # Safely get ID for display/lookup
        ttp_name = ttp.get('name', 'Unknown TTP') # Safely get name
        
        # For MITRE data, the ID might be inside external_references
        # Extract the proper ID for display and enrichment lookup
        if not ttp_id and current_library_path == ATTACK_DATASET_FILE:
             ext_refs = ttp.get('external_references', [])
             for ref in ext_refs:
                 if ref.get('source_name') == 'mitre-attack':
                     ttp_id = ref.get('external_id')
                     break # Found the MITRE ID
        
        # Define a fallback ID if absolutely necessary (should be rare)
        display_id = ttp_id if ttp_id else f"(No ID Found - {ttp_name[:20]}...)" 

        # Use the extracted/default ttp_id for enrichment lookup if available
        enrich = attack_map.get(ttp_id) if ttp_id else None 
        
        with st.expander(f"{display_id} - {ttp_name}"): # Use display_id and ttp_name
            st.write(f"**Description:** {ttp.get('description', 'N/A')}") # Use .get()
            if enrich:
                st.write(f"- **Tactic:** {enrich.get('tactic', 'N/A')}") # Use .get()
                # Ensure URL exists before creating markdown link
                if enrich.get('url'):
                     st.markdown(f"- **More Info:** [{enrich.get('url')}]({enrich.get('url')})") 
            
            # Platform info might be in 'x_mitre_platforms' for ATT&CK data
            platforms = ttp.get('platform') # Check standard key first
            if not platforms and current_library_path == ATTACK_DATASET_FILE:
                 platforms = ttp.get('x_mitre_platforms') # MITRE specific key
            
            if platforms:
                 # If platforms is a list, join it; otherwise, display as is
                 platform_str = ", ".join(platforms) if isinstance(platforms, list) else str(platforms)
                 st.write(f"- **Platform(s):** {platform_str}")
                 
            # Show raw command only if available (likely only in ttp_library.json format)
            if ttp.get('command'):
                 st.code(ttp.get('command'), language='bash') # Display command if present
elif current_library_path:
     st.info("No TTPs were loaded from the selected library.")
# Don't show the 'Browse' section if no library was selected
# else:
#      st.info("Select a TTP library from the sidebar to browse TTPs.")

st.markdown("## 📜 Recently Executed TTPs")

executed_ttps = load_executions()

if executed_ttps:
    for ttp in reversed(executed_ttps[-10:]):  
        with st.expander(f"{ttp['timestamp']} — {ttp['id']} ({ttp['name']})"):
            st.write(f"**Command:** `{ttp['command']}`")
            st.write(f"**Platform:** {ttp['platform']}")
            st.write(f"**Dry Run:** {ttp['dry_run']}")
            if ttp.get("output"):
                st.code(ttp["output"], language="bash")
            if ttp.get("error"):
                st.error(ttp["error"])
else:
    st.write("No TTPs executed yet.")

st.markdown("---")
st.subheader("📜 Execution Logs (Latest Run)")

def get_latest_run_base_filename():
    main_log_files = glob.glob(os.path.join(LOG_DIR, "threat_bot_*.log"))
    if not main_log_files:
        return None
    latest_main_log = max(main_log_files, key=os.path.getctime)
    base_filename = os.path.basename(latest_main_log)[:-4] 
    return base_filename

latest_run_base = get_latest_run_base_filename()

if latest_run_base:
    st.caption(f"Displaying logs for run: `{latest_run_base}`")
    run_log_files = glob.glob(os.path.join(LOG_DIR, f"{latest_run_base}*"))

    if run_log_files:
        log_tabs = st.tabs([os.path.basename(f) for f in sorted(run_log_files)])

        for i, log_file_path in enumerate(sorted(run_log_files)):
            with log_tabs[i]:
                st.caption(f"Showing last 20 lines of `{os.path.basename(log_file_path)}`")
                try:
                    with open(log_file_path, "r", encoding='utf-8') as f:
                        lines = f.readlines()
                        last_lines = lines[-20:] 
                        st.text("".join(last_lines))
                except Exception as e:
                    st.error(f"Could not read log file {os.path.basename(log_file_path)}: {e}")
        st.caption("⏱️ Refresh page to update logs for the latest run.")
    else:
        st.warning(f"Found latest run '{latest_run_base}' but no associated log files.")
else:
    st.warning("No log files found in the `logs/` directory.")

# Footer
st.markdown("---")
st.markdown("Made with ❤️ by your local threat emulation bot")
