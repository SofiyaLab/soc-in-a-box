import xmltodict

report = []
report.append("# SOC-in-a-Box Security Report\n")

# Counters
high_count = 0
medium_count = 0
low_count = 0

# =========================
# NMAP ANALYSIS
# =========================
try:
    with open("scans/scan.xml", "r") as file:
        data = xmltodict.parse(file.read())

    host = data["nmaprun"]["host"]
    ports = host.get("ports", {}).get("port", [])

    if isinstance(ports, dict):
        ports = [ports]

    if not ports:
        report.append("No open ports detected.\n")

    else:
        for port in ports:
            port_id = port.get("@portid")
            protocol = port.get("@protocol")
            state = port.get("state", {}).get("@state")
            service = port.get("service", {}).get("@name", "unknown")

            if state != "open":
                continue

            # Risk logic
            if service == "ssh":
                severity = "HIGH"
                risk = "Remote access (SSH) exposed"
                fix = "Disable password login, use SSH keys, restrict IP access"

            elif service == "ms-wbt-server":
                severity = "HIGH"
                risk = "RDP exposed (remote desktop)"
                fix = "Disable RDP or restrict with firewall/VPN"

            elif service == "ftp":
                severity = "HIGH"
                risk = "FTP service exposed (insecure protocol)"
                fix = "Disable FTP or switch to SFTP"

            elif service in ["http", "https"]:
                severity = "MEDIUM"
                risk = "Web service exposed"
                fix = "Ensure secure configuration and patch vulnerabilities"

            elif service in ["mysql", "postgresql"]:
                severity = "HIGH"
                risk = "Database service exposed"
                fix = "Restrict access to internal network only"

            else:
                severity = "LOW"
                risk = "Unknown or less common service"
                fix = "Review service necessity"

            # Count severity
            if severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            else:
                low_count += 1

            # Add to report
            report.append(f"## [{severity}] Port {port_id}/{protocol} ({service})")
            report.append(f"**Risk:** {risk}")
            report.append(f"**Fix:** {fix}\n")

except FileNotFoundError:
    report.append("Nmap scan file not found.\n")

# =========================
# SUMMARY
# =========================
report.insert(1, f"**High Risk:** {high_count}")
report.insert(2, f"**Medium Risk:** {medium_count}")
report.insert(3, f"**Low Risk:** {low_count}\n")

# =========================
# ZAP ANALYSIS (Summary Only)
# =========================
report.append("\n---\n")
report.append("## OWASP ZAP Summary\n")

try:
    with open("reports/zap_report.html", "r", encoding="utf-8") as zap:
        content = zap.read()

        warning_count = content.count("WARN")
        report.append(f"Detected {warning_count} potential web vulnerabilities.\n")
        report.append("See full details in zap_report.html\n")

except FileNotFoundError:
    report.append("ZAP report not found.\n")

# =========================
# SAVE FINAL REPORT
# =========================
with open("reports/final_report.md", "w") as file:
    file.write("\n".join(report))

print("Final report created: reports/final_report.md")
