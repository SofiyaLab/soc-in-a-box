import xmltodict

# Load Nmap XML file
with open("scans/scan.xml", "r") as file:
    data = xmltodict.parse(file.read())

# Extract host and ports
host = data["nmaprun"]["host"]
ports = host.get("ports", {}).get("port", [])

# Handle case where only one port exists
if isinstance(ports, dict):
    ports = [ports]

# Create report list
report = []
high_count = 0
medium_count = 0
low_count = 0
report.append("# SOC-in-a-Box Security Report\n")

# If no ports found
if not ports:
    report.append("No open ports detected.")

else:
    for port in ports:
        port_id = port.get("@portid")
        protocol = port.get("@protocol")
        state = port.get("state", {}).get("@state")
        service = port.get("service", {}).get("@name", "unknown")

        # Skip closed ports
        if state != "open":
            continue

        # ✅ Improved risk logic (service-based)
        if service in ["ssh"]:
            severity = "HIGH"
            risk = "Remote access (SSH) exposed"
            fix = "Disable password login, use SSH keys, restrict IP access"

        elif service in ["ms-wbt-server"]:
            severity = "HIGH"
            risk = "RDP exposed (remote desktop)"
            fix = "Disable RDP or restrict with firewall/VPN"

        elif service in ["ftp"]:
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

        # ✅ Count severity
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

# Save report
with open("reports/report.md", "w") as file:
    file.write("\n".join(report))

print("Report created: reports/report.md")

