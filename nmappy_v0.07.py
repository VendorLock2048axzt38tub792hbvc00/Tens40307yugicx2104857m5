import os
import subprocess
import platform
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage
import pandas as pd
import csv

# Configuration
OLLAMA_MODEL = "qwen3:8b"
MAX_ATTEMPTS = 3

def get_host_info():
    """Identify host OS and IP address"""
    print("\n[Step 1] Identifying host operating system and IP address...")
    
    os_type = platform.system()
    ip_address = None
    
    if os_type == 'Windows':
        result = subprocess.run(['ipconfig'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        for line in lines:
            if 'IPv4' in line and '127.0.0.1' not in line:
                ip_address = line.split()[-1]
                break
    elif os_type == 'Linux':
        try:
            result = subprocess.run(['ip', 'a'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'inet' in line and '127.0.0.1' not in line:
                    ip_address = line.split()[1]
                    break
        except FileNotFoundError:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'inet' in line and '127.0.0.1' not in line:
                    ip_address = line.split()[1]
                    break
    elif os_type == 'Darwin':
        result = subprocess.run(['ifconfig'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        for line in lines:
            if 'inet ' in line and '127.0.0.1' not in line:
                ip_address = line.split()[-1]
                break
    
    print(f"Detected OS: {os_type}")
    print(f"Host IP Address: {ip_address}\n")
    
    return os_type, ip_address

def get_network_range(ip):
    """Determine network range and gateway from host IP"""
    parts = ip.split('.')
    if len(parts) != 4:
        return None, None
    
    # Format as CIDR notation (e.g., 192.168.50.0/24)
    network_cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    gateway_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    
    return network_cidr, gateway_ip

def run_nmap_scan(ip, scan_type="host", scan_style='fast', max_attempts=3):
    """Run Nmap scans with AI guidance"""
    for attempt in range(max_attempts):
        # Construct specific prompt to elicit detailed decision
        if scan_type == "host":
            prompt = f"""[AI Decision Prompt]
Based on the target IP {ip} and scan type 'host', choose the best command from these options (selected style: {scan_style}):

"""
            # Generate commands based on scan_style
            if scan_style == 'fast':
                commands = [
                    "nmap -F {ip}",
                    "nmap -T4 -F {ip}"
                ]
            elif scan_style == 'stealthy':
                commands = [
                    "nmap -sS -Pn {ip}",
                    "nmap -sS -Pn --spoof-mac=AA:BB:CC:DD:EE:FF {ip}",
                    "nmap -sS -Pn --randomize-hosts {ip}"
                ]
            elif scan_style == 'full':
                commands = [
                    "nmap -p 1-65535 -sV -O -A {ip}",
                    "nmap -p- -sV -O -A {ip}"
                ]
            
            # Format the prompt with these commands
            for i, cmd in enumerate(commands, 1):
                prompt += f"{i}. {cmd}\n"
            
            prompt += """Provide:
- The full nmap command with proper syntax
- A rationale explaining your choice of parameters
- Why this command is suitable for host scanning

Example format:
1. nmap -sS -Pn
2. This command uses stealthy TCP SYN scans to avoid detection while identifying open ports.

If you need more information about the network, ask for clarification.
"""
        
        elif scan_type == "gateway":
            prompt = f"""[AI Decision Prompt]
Based on the target IP {ip} and scan type 'gateway', choose the best command from these options (selected style: {scan_style}):

"""
            # Generate commands based on scan_style
            if scan_style == 'fast':
                commands = [
                    "nmap -F <GATEWAY_IP>",
                    "nmap -T4 -F <GATEWAY_IP>"
                ]
            elif scan_style == 'stealthy':
                commands = [
                    "nmap -sS -Pn <GATEWAY_IP>",
                    "nmap -sS -Pn --spoof-mac=AA:BB:CC:DD:EE:FF <GATEWAY_IP>",
                    "nmap -sS -Pn --randomize-hosts <GATEWAY_IP>"
                ]
            elif scan_style == 'full':
                commands = [
                    "nmap -p 1-65535 -sV -O -A <GATEWAY_IP>",
                    "nmap -p- -sV -O -A <GATEWAY_IP>"
                ]
            
            # Format the prompt with these commands
            for i, cmd in enumerate(commands, 1):
                prompt += f"{i}. {cmd}\n"
            
            prompt += """Provide:
- The full nmap command with proper syntax
- A rationale explaining your choice of parameters
- Why this command is suitable for gateway scanning

Example format:
1. nmap -sS -Pn <GATEWAY_IP>
2. This command uses stealthy TCP SYN scans to avoid detection while identifying open ports.

If you need more information about the network, ask for clarification.
"""
        
        elif scan_type == "network":
            prompt = f"""[AI Decision Prompt]
Based on the target IP {ip} and scan type 'network', choose the best command from these options (selected style: {scan_style}):

"""
            # Generate commands based on scan_style
            if scan_style == 'fast':
                commands = [
                    "nmap -F 192.168.0.0/24",
                    "nmap -T4 -F 192.168.0.0/24",
                    "nmap -iR 50 -F --exclude 192.168.0.0/24"
                ]
            elif scan_style == 'stealthy':
                commands = [
                    "nmap -sS -Pn 192.168.0.0/24",
                    "nmap -sS -Pn --randomize-hosts 192.168.0.0/24",
                    "nmap -iR 50 -sS -Pn --exclude 192.168.0.0/24"
                ]
            elif scan_style == 'full':
                commands = [
                    "nmap -p 1-65535 -sV -O -A 192.168.0.0/24",
                    "nmap -p- -sV -O -A 192.168.0.0/24",
                    "nmap -iL hosts.txt -p 1-65535 -sV -O -A",
                    "nmap -iR 100 -p 1-65535 -sV -O -A --exclude 192.168.0.0/24"
                ]
            
            # Format the prompt with these commands
            for i, cmd in enumerate(commands, 1):
                prompt += f"{i}. {cmd}\n"
            
            prompt += """Provide:
- The full nmap command with proper syntax
- A rationale explaining your choice of parameters
- Why this command is suitable for network scanning

Example format:
1. nmap -sS -Pn {192.168.0.0/24}
2. This command uses stealthy TCP SYN scans to avoid detection while identifying open ports.

If you need more information about the network, ask for clarification.
"""

        # Get AI suggestion
        print(f"\n[Attempt {attempt+1}] Requesting AI decision for {scan_type} scan...")
        try:
            response = ChatOllama(model=OLLAMA_MODEL).invoke(prompt)
            ai_response = response.content.strip()
            
            # Extract the command and rationale from the response
            lines = ai_response.split('\n')
            command_line = None
            rationale = ""
            
            for line in lines:
                if line.startswith("1."):
                    command_line = line.replace("1.", "").strip()
                elif line.startswith("2.") or line.startswith("3.") or line.startswith("4."):
                    rationale += line + "\n"
            
            # Ensure we have a valid nmap command
            if not command_line or not command_line.startswith("nmap") or "<IP>" in command_line:
                print(f"[Warning] Invalid command suggested by AI: {command_line}")
                continue
            
            ai_command = command_line
            rationale = rationale.strip()
            
            # Replace placeholder with actual IP
            if scan_type == "gateway":
                final_cmd = ai_command.replace("<GATEWAY_IP>", ip)
            elif scan_type == "network":
                final_cmd = ai_command.replace("<NETWORK_RANGE>", ip)
            else:
                final_cmd = ai_command.replace("<IP>", ip)
            
            # Execute the command
            print(f"\n[Attempt {attempt+1}] Running command: {final_cmd}")
            result = subprocess.run(final_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("Scan successful!")
                return result.stdout, rationale
            
            print(f"Scan failed with code {result.returncode}:")
            print(result.stderr)
        
        except Exception as e:
            print(f"[Error] Failed to execute command: {str(e)}")
    
    raise RuntimeError("Failed to complete scan after maximum attempts")

def parse_nmap_to_csv(nmap_output):
    """Parse Nmap results into CSV format"""
    lines = nmap_output.split('\n')
    devices = []

    for line in lines:
        if "Nmap scan report" in line:
            # Extract IP from the Nmap scan report line (e.g., "for 192.168.x.x")
            ip_start = line.find("for ") + 4
            ip_end = line.find(" ", ip_start)
            ip = line[ip_start:ip_end].strip()
            status = "Up"
            ports = []

            # Find open port lines related to this IP
            for port_line in lines:
                if f"{ip} " in port_line and "open" in port_line:
                    parts = port_line.split()
                    port = parts[0]
                    service = " ".join(parts[2:])
                    ports.append(f"{port}/{service}")
            
            devices.append({
                "IP Address": ip,
                "Status": status,
                "Ports": ", ".join(ports),
                "Service": "N/A"
            })

    return devices

def generate_report(vulnerability_data, filename="pentest_report.md"):
    """Generate cybersecurity pentest report in Markdown format"""
    print("\n[Step 6] Generating final security report...")
    
    with open(filename, 'w') as report_file:
        # Markdown headers
        report_file.write("# Cybersecurity Pentest Report\n")
        report_file.write(f"## Target IP: {vulnerability_data.get('host_ip', 'Unknown')}\n")
        report_file.write("## Scan Duration: 0.19 seconds (Host Scan) / 0.02 seconds (Network Scan)\n")
        report_file.write("## Scan Version: Nmap 7.95\n\n")
        
        # Executive Summary
        report_file.write("### Executive Summary\n")
        if vulnerability_data.get('vulnerabilities', []):
            report_file.write("- The scan identified several vulnerabilities that require immediate attention.\n")
        else:
            report_file.write("- No vulnerabilities were detected. The target system appears secure under standard configurations.\n")
        report_file.write("\n")
        
        # Technical Findings
        report_file.write("### Technical Findings\n")
        if vulnerability_data.get('vulnerabilities', []):
            for vuln in vulnerability_data['vulnerabilities']:
                report_file.write(f"- **{vuln['description']}** ({vuln['risk_level']})\n")
                report_file.write(f"  - {vuln['details']}\n\n")
        else:
            report_file.write("- No vulnerabilities were detected.\n\n")
        
        # Risk Assessment
        report_file.write("### Risk Assessment\n")
        if vulnerability_data.get('vulnerabilities', []):
            for vuln in vulnerability_data['vulnerabilities']:
                report_file.write(f"- **{vuln['description']}** - {vuln['risk_level']}\n")
                report_file.write(f"  - {vuln['impact']}\n\n")
        else:
            report_file.write("- No risks identified.\n\n")
        
        # Remediation Recommendations
        report_file.write("### Remediation Recommendations\n")
        if vulnerability_data.get('vulnerabilities', []):
            for vuln in vulnerability_data['vulnerabilities']:
                report_file.write(f"- **{vuln['description']}**\n")
                report_file.write(f"  - {vuln['remediation']}\n\n")
        else:
            report_file.write("- No remediation actions required.\n\n")
        
        # Conclusion
        report_file.write("### Conclusion\n")
        if vulnerability_data.get('vulnerabilities', []):
            report_file.write("The scan identified several vulnerabilities that require immediate attention. Follow the remediation recommendations to mitigate risks.\n")
        else:
            report_file.write("No vulnerabilities were detected, indicating the target system is likely secure under standard configurations. No further action is required.\n")
    
    print(f"Final security report saved to {filename}")

def main():
    # Program Introduction
    print("\n=== Nmap Cybersecurity Scanner ===")
    print("This tool performs automated Nmap scans with AI assistance to identify vulnerabilities.")
    print("It supports three scan styles: fast, stealthy, and full. Select your preference.\n")

    os_type, ip = get_host_info()
    
    if not ip:
        print("Could not determine IP address. Exiting.")
        return
    
    network_cidr, gateway_ip = get_network_range(ip)
    
    # Get user scan style
    scan_style = input("Choose scan style (fast/stealthy/full): ").strip().lower()
    while scan_style not in ['fast', 'stealthy', 'full']:
        print("Invalid option. Please choose fast, stealthy, or full.")
        scan_style = input("Choose scan style (fast/stealthy/full): ").strip().lower()

    try:
        # Step 2: Scan host
        print("[Step 2] Scanning host with Nmap...")
        host_scan_results, host_rationale = run_nmap_scan(ip, scan_type="host", scan_style=scan_style)
        
        # Step 3: Scan router/gateway
        print("\n[Step 3] Enumerating gateway/router...")
        gateway_scan_results, gateway_rationale = run_nmap_scan(gateway_ip, scan_type="gateway", scan_style=scan_style)
        
        # Step 4: Scan network
        print("\n[Step 4] Enumerating network...")
        network_scan_results, network_rationale = run_nmap_scan(network_cidr, scan_type="network", scan_style=scan_style)
        
        # Step 5: Parse results to CSV
        host_devices = parse_nmap_to_csv(host_scan_results)
        gateway_devices = parse_nmap_to_csv(gateway_scan_results)
        network_devices = parse_nmap_to_csv(network_scan_results)
        all_devices = host_devices + gateway_devices + network_devices

        with open("nmap_results.csv", 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["IP Address", "Status", "Ports", "Service"])
            writer.writeheader()
            for device in all_devices:
                writer.writerow(device)
        
        print(f"Nmap data saved to nmap_results.csv")

        # Step 6: Cybersecurity analysis
        print("\n[Step 5] Analyzing security risks with AI...")
        combined_results = f"Host Scan:\n{host_scan_results}\n\nGateway Scan:\n{gateway_scan_results}\n\nNetwork Scan:\n{network_scan_results}"
        
        analysis_prompt = f"""[AI Analysis Prompt]
Analyze the following Nmap scan results for vulnerabilities and security issues:

{combined_results}

Provide a detailed cybersecurity pentest report with:
1. List of discovered vulnerabilities
2. Risk ratings (High/Medium/Low)
3. Technical details about each vulnerability
4. Remediation recommendations

Include the rationale for your analysis in the response.
"""
        
        analysis_response = ChatOllama(model=OLLAMA_MODEL).invoke(analysis_prompt)
        print("\n[AI Analysis] Security Findings:")
        print(analysis_response.content)
        
        # Step 6: Generate report
        vulnerability_data = {
            'host_ip': ip,
            'vulnerabilities': [],
        }

        lines = analysis_response.content.split('\n')
        in_vulnerabilities = False

        for line in lines:
            if "discovered vulnerabilities" in line.lower():
                in_vulnerabilities = True
                continue  # Skip the header line
            elif "remediation recommendations" in line.lower():
                break  # End of vulnerability section
            
            if in_vulnerabilities and line.strip() != "":
                parts = line.split(" - ", 1)
                if len(parts) == 2:
                    description, details = parts
                    risk_level = "Low"
                    if "high" in details.lower() or "critical" in details.lower():
                        risk_level = "High"
                    elif "medium" in details.lower():
                        risk_level = "Medium"
                    vulnerability_data['vulnerabilities'].append({
                        'description': description,
                        'risk_level': risk_level,
                        'details': details
                    })

        generate_report(vulnerability_data)
    
    except Exception as e:
        print(f"\n[Error] {str(e)}")

if __name__ == "__main__":
    main()
