import os
import subprocess
import glob
import time
import streamlit as st
import json
from utils import load_attack_mapping


# Page settings
st.set_page_config(page_title="Threat Emulation Dashboard", layout="wide")
st.title("🚨 Threat Emulation Live Dashboard")

st.sidebar.header("⚙️ Emulation Control")

# Add a selector for the TTP dataset
ttp_set_options = ["ttp_library.json", "attack-dataset.json"] # Add more if needed
selected_ttp_set = st.sidebar.selectbox(
    "Select TTP Set:",
    ttp_set_options,
    index=0  # Default to ttp_library.json
)

dry_run = st.sidebar.checkbox("Dry Run Mode", value=True)

if st.sidebar.button("▶️ Run threat_bot.py"):
    st.sidebar.info(f"Executing threat_bot.py with {selected_ttp_set}...")
    try:
        # Use 'python' for Windows, pass selected TTP set
        cmd = ["python", "threat_bot.py", "--ttp-set", selected_ttp_set]
        if dry_run:
            cmd.append("--dry-run")
        subprocess.Popen(cmd)  # non-blocking
        st.sidebar.success("Execution started!")
    except FileNotFoundError:
        st.sidebar.error("Error: 'python' command not found. Is Python installed and in PATH?")
    except Exception as e:
        st.sidebar.error(f"Failed to run: {e}")


def load_executions(file_path='execution_log.json'):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        st.info("ℹ️ No executed TTPs yet.")
        return []

# Function to load TTPs from a JSON file or fallback to test data
def load_ttps(file_path='ttp_library.json'):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        st.warning("⚠️ 'ttp_library.json' not found. Loading sample data instead.")
        return [
            {
                "id": "T1003",
                "name": "Credential Dumping",
                "description": "Extracts credentials from LSASS memory."
            },
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "description": "Executes commands using scripting environments like PowerShell or Bash."
            },
            {
                "id": "T1071",
                "name": "Application Layer Protocol",
                "description": "Uses HTTP/S or DNS for command and control communication."
            }
        ]

# Load data
# Note: Dashboard display currently loads default ttp_library.json
# Execution uses the selected TTP set.
ttps = load_ttps() # Consider updating this if you want the display to match selection
attack_map = load_attack_mapping()

# Sidebar filters
st.sidebar.header("🔍 Filter TTPs")
search_term = st.sidebar.text_input("Search by ID or Name")

# Filter logic
if search_term:
   ttps = [
        t for t in ttps
        if search_term.lower() in t["id"].lower()
        or search_term.lower() in t["name"].lower()
        or attack_map.get(t["id"], {}).get("tactic", "").lower().find(search_term.lower()) != -1
    ]

# Display TTPs in a table
if ttps:
    for ttp in ttps:
        enrich = attack_map.get(ttp['id'])
        with st.expander(f"{ttp['id']} - {ttp['name']}"):
            st.write(f"**Description:** {ttp['description']}")
            if enrich:
                st.markdown(f"- **Tactic:** {enrich['tactic'].capitalize()}")
                st.markdown(f"- **Technique Name:** {enrich['name']}")
                st.markdown(f"- **More Info:** [{enrich['url']}]({enrich['url']})")
else:
    st.error("❌ No TTPs match your search.")
st.markdown("## 📜 Recently Executed TTPs")

executed_ttps = load_executions()

if executed_ttps:
    for ttp in reversed(executed_ttps[-10:]):  # Show last 10
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
st.subheader("📜 Execution Logs (Latest)")

def get_latest_log_file():
    log_files = glob.glob("logs/threat_bot_*.log")
    if not log_files:
        return None
    return max(log_files, key=os.path.getctime)

log_file = get_latest_log_file()

if log_file:
    st.caption(f"Showing last 10 lines of `{os.path.basename(log_file)}`")
    with open(log_file, "r", encoding='utf-8') as f:
        lines = f.readlines()
        last_lines = lines[-10:]
        st.text("".join(last_lines))
        st.caption("⏱️ Refresh page to update logs.")
else:
    st.warning("No log files found in the `logs/` directory.")

# Footer
st.markdown("---")
st.markdown("Made with ❤️ by your local threat emulation bot")
