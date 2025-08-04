# PingSweep

## 📌 Overview

A Python network scanning tool with both GUI and CLI interfaces that allows you to:

- Discover active devices on your local network using ARP
- Perform ICMP ping sweeps
- Switch between graphical and command-line interfaces

## 🚀 Installation

1. Ensure you have Python 3.6+ installed

2. Install required packages:

    ```bash
    pip install customtkinter scapy

## 🖥️ Usage

1. Method 1: Using run.py (Interactive Mode)

    ```bash
    python run.py

Then choose between GUI or CLI interface when prompted.

2. Method 2: Direct GUI Execution

    ```bash
    python gui_version.py

3. Method 3: Direct CLI Execution

    ```bash
    python cli_version.py
    ```

## 🛠️ Features

- ARP Scanning: Discover devices on local network
- ICMP Ping: Check host availability
- Dual Interface: Choose between GUI and CLI
- Customizable:
  - Set IP range
  - Adjust timeout
  - Select scan method

### 📂 File Structure

```text
PingSweep/
│
├── run.py             # Main launcher (GUI/CLI selector)
├── gui_version.py     # Graphical interface version
├── cli_version.py     # Command line interface version
├── README.md          # This documentation
└── requirements.txt   # Dependencies
```

## ⁉️ Common Issues

If you get permission errors on Linux/macOS, try:

```bash
sudo python run.py
```

- For Windows firewall alerts, allow Python through your firewall when prompted.
