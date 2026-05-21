import xmltodict

with open("scans/scan.xml", "r") as file:
    data = xmltodict.parse(file.read())

host = data["nmaprun"]["host"]
ports = host.get("ports", {}).get("port", [])

if isinstance(ports, dict):
    ports = [ports]

report = []
report.append("# SOC-in-a-Box Security Report\n")

if not ports:
    report.append("No open ports detected.")
else:
    for port in ports:
        port_id = port.get("@portid")
        protocol = port.get("@protocol")
        state = port.get("state", {}).get("@state")
        service = port.get("service", {}).get("@name", "unknown")

        if state != "open":
            continue

        if port_id in ["22", "3389"]:
            severity = "HIGH"
            risk = "Remote access service exposed"
        elif port_id in ["80", "443"]:
            severity = "MEDIUM"
            risk = "Web service exposed"
        else:
            severity = "LOW"
            risk = "Unknown or less common service"

        report.append(f"## [{severity}] Port {port_id}/{protocol} ({service})")
        report.append(f"**Risk:** {risk}")
        report.append("**Fix:** Restrict access using firewall or disable if not needed.")
        report.append("")

with open("reports/report.md", "w") as file:
    file.write("\n".join(report))

print("Report created: report.md")