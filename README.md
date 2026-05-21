# SOC-in-a-Box 🔐

## Project Overview

This project simulates a basic Security Operations Center (SOC) workflow.

It scans a system using Nmap and generates a human-readable security report using Python.
## Tools Used

- Python
- Nmap
- Visual Studio Code
## How to Run

Run an Nmap scan:

```bash
nmap -sV -oX scans/scan.xml 127.0.0.1
Generate the report:

```bash
python scripts/analyzer.py

## Sample Output
[HIGH] Port 3389/tcp
Risk: Remote access service exposed
Fix: Restrict access using firewall or disable if not needed.

## Safety Note

Only scan systems you own or have permission to test.


