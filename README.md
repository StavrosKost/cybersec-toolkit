# Threat Emulator Bot

This project provides a tool to simulate cybersecurity threats by executing Tactics, Techniques, and Procedures (TTPs) based on predefined libraries and scenarios. It features a user-friendly web dashboard built with Streamlit for easy interaction and a command-line interface for more direct execution.

**Core Features:**

*   **Web Dashboard:** An interactive interface (`dashboard.py`) to:
    *   Select and browse TTP libraries (`ttp_library.json`).
    *   Select and execute predefined attack scenarios (`attack_scenarios.json`).
    *   Browse the MITRE ATT&CK dataset (`attack_dataset.json`) for reference (non-executable).
    *   Execute individual TTPs or a random selection from the chosen library.
    *   View execution logs and results in real-time.
*   **Command-Line Execution:** A script (`threat_bot.py`) for running TTPs directly from the terminal.
*   **TTP Libraries:** Define executable commands for different platforms (`windows`, `linux`, `macos`) in JSON format (`ttp_library.json`).
*   **Attack Scenarios:** Define sequences of TTPs to simulate specific attack chains (`attack_scenarios.json`).
*   **MITRE ATT&CK Reference:** Includes the MITRE ATT&CK dataset (`attack_dataset.json`) for browsing TTP details, tactics, and descriptions within the dashboard. **Note:** This dataset does *not* contain executable commands and cannot be run by the emulator.
*   **Logging:** Records detailed execution logs, including commands run, output, errors, and timestamps in the `logs/` directory and a consolidated `execution_log.json`.

## Setup

1.  **Clone the Repository:**
    ```bash
    git clone <your-repository-url>
    cd threat_emulator_bot
    ```
2.  **Install Dependencies:** Ensure you have Python 3.x installed.
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### 1. Web Dashboard (Recommended)

This is the easiest way to interact with the Threat Emulator.

```bash
streamlit run dashboard.py
```

This will launch the dashboard in your web browser. From there, you can:

*   Use the sidebar dropdown to select:
    *   A TTP library (e.g., `ttp_library.json`).
    *   An attack scenario file (`attack_scenarios.json`).
    *   The MITRE ATT&CK Dataset (`attack_dataset.json`) for browsing.
*   If a TTP library is selected:
    *   Browse the available TTPs using the search bar.
    *   Select specific TTPs to run.
    *   Choose a number of random TTPs to run.
    *   Click "▶️ Run threat_bot.py" to execute the selection.
*   If a scenario file is selected:
    *   Choose a specific scenario from the dropdown.
    *   Click "▶️ Run threat_bot.py" to execute the scenario.
*   If the MITRE ATT&CK dataset is selected:
    *   Browse TTPs using the search bar.
    *   **Note:** The execution button will be disabled as this dataset is for reference only.
*   View the execution output and logs directly in the dashboard.

### 2. Command-Line Interface (`threat_bot.py`)

Use this for direct script execution.

**Arguments:**

*   `--ttp-library FILE`: Path to the TTP library JSON file (e.g., `ttp_library.json`).
*   `--scenario-file FILE`: Path to the attack scenario JSON file (e.g., `attack_scenarios.json`).
*   `--scenario-name NAME`: Name of the scenario to execute from the scenario file.
*   `--ttp-ids ID [ID ...]`: Specific TTP IDs from the library to execute.
*   `--run-all`: Execute all compatible TTPs from the specified library.
*   `--random N`: Execute N randomly selected compatible TTPs from the library.
*   `--log-dir PATH`: Directory to store log files (defaults to `./logs`).

**Examples:**

*   **Run specific TTPs from the default library:**
    ```bash
    python threat_bot.py --ttp-library ttp_library.json --ttp-ids T1059.001 T1063
    ```
*   **Run 5 random TTPs from the default library:**
    ```bash
    python threat_bot.py --ttp-library ttp_library.json --random 5
    ```
*   **Run all compatible TTPs from the default library:**
    ```bash
    python threat_bot.py --ttp-library ttp_library.json --run-all
    ```
*   **Run a specific scenario:**
    ```bash
    python threat_bot.py --scenario-file attack_scenarios.json --scenario-name "Example Scenario 1: Recon & Sleep"
    ```

**Note:** You must provide *either* a `--ttp-library` *or* a `--scenario-file` along with relevant execution options (`--ttp-ids`, `--run-all`, `--random`, `--scenario-name`).

## Configuration Files

*   **`ttp_library.json`:** Defines executable TTPs. Each object requires:
    *   `id` (string): Technique ID (e.g., "T1059.001").
    *   `name` (string): Descriptive name.
    *   `description` (string): Explanation.
    *   `platform` (string): Target OS (`"windows"`, `"linux"`, `"macos"`, `"all"`).
    *   `command` (string): The command to execute.
    *   Optional: `tactic` (string), `url` (string).
*   **`attack_scenarios.json`:** Defines named sequences of TTP IDs to run. Structure:
    ```json
    {
      "Scenario Name 1": ["TTP_ID_1", "TTP_ID_2"],
      "Scenario Name 2": ["TTP_ID_A", "TTP_ID_B", "TTP_ID_C"]
    }
    ```
*   **`attack_dataset.json`:** The MITRE ATT&CK dataset (STIX format). Used for reference in the dashboard, **not for execution**.
*   **`requirements.txt`:** Lists Python dependencies (primarily `streamlit`).

## Logging

*   Individual execution logs are stored in the `logs/` directory (or the directory specified by `--log-dir`).
*   A consolidated summary of all executions run via the dashboard is stored in `execution_log.json`.

## (Optional) Log Analyzer

The `log_analyzer.py` script can be used to parse and summarize logs from the `logs/` directory.

*   **Analyze all logs:**
    ```bash
    python log_analyzer.py
    ```
*   **Analyze logs for a specific date:**
    ```bash
    python log_analyzer.py --date YYYY-MM-DD
    ```
