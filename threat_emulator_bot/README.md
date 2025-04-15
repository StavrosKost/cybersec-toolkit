# 🐙 Threat Emulation Bot

A customizable adversary simulation tool that randomly executes TTPs (Tactics, Techniques, and Procedures) to test EDR, SIEM, and detection rules.

---

## 🚀 Features

- 🧩 **Custom TTP Sets**: Swap out behavior libraries for Linux, Windows, stealth, etc.
- 🪵 **Logging**: Saves execution details, outputs, and errors to timestamped logs.
- 🖥️ **OS Detection Banner**: Prints system info and ensures only compatible commands run.
- 🔀 **Randomized Execution**: Choose how many TTPs to run per session.
- 🧪 **Dry Run Mode**: Preview without execution (safe for demos).

---

## 📦 Setup

```bash
git clone https://github.com/yourname/threat-emulation-bot.git
cd threat-emulation-bot
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt  # None needed by default unless adding APIs/tools
