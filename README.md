# SOC-in-a-Box 🔐

## Project Overview

SOC-in-a-Box is a practical cybersecurity lab that simulates a Security Operations Center (SOC) workflow.

The project integrates network scanning, vulnerability detection, and automated analysis to identify security risks and generate structured reports.

---

## Key Capabilities

- Network reconnaissance using Nmap  
- Automated threat analysis using Python  
- Web application vulnerability scanning using OWASP ZAP  
- Risk classification (HIGH / MEDIUM / LOW)  
- Security recommendations for each finding  
- Multi-format reporting (Markdown + HTML)  

---

## Technologies Used

- Python  
- Nmap  
- OWASP ZAP  
- Docker  
- Git & GitHub  

---

## Project Architecture


Scan → Analyze → Classify → Report


---

## Project Structure


soc-project/
├── scans/
│ └── scan.xml
├── reports/
│ ├── report.md
│ └── zap_report.html
├── scripts/
│ └── analyzer.py
└── README.md


---

## How to Run

### 1. Network Scan (Nmap)

```bash
nmap -sV -oX scans/scan.xml 127.0.0.1
2. Analyze Results (Python)
python scripts/analyzer.py
3. Web Vulnerability Scan (OWASP ZAP)
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost
4. Generate ZAP Report
docker run -t -v ${PWD}/reports:/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost -r zap_report.html
Sample Output
# SOC-in-a-Box Security Report

High Risk: 1
Medium Risk: 1
Low Risk: 0

## [HIGH] Port 22/tcp (ssh)
Risk: Remote access (SSH) exposed
Fix: Disable password login, use SSH keys, restrict IP access
Web Security Findings (OWASP ZAP)
Missing security headers (CSP, X-Content-Type-Options)
No clickjacking protection
Cache control issues
Missing permissions policy
Security Considerations

This project is for educational use only.

Only scan:

Localhost environments
Personal lab systems
Authorized testing environments
Future Improvements
Combine Nmap and ZAP findings into one report
Add dashboard visualization (Streamlit)
Integrate SIEM tools (Wazuh / ELK)
Automate continuous scanning

Author
Sofiya. 
