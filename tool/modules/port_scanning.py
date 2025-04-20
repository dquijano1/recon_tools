import json
import nmap
import subprocess

def get_ips_from_json(domain):
    filepath = f"results/{domain.replace('.', '_')}.json"
    ips = set()

    try:
        with open(filepath, 'r') as f:
            data = json.load(f)

        dns_lookup = data.get("dns_lookup", {})
        for record_type in ["A", "AAAA"]:
            if record_type in dns_lookup:
                for dns_server, entries in dns_lookup[record_type].items():
                    for entry in entries:   
                        ip = entry.get("ip")
                        if ip:
                            ips.add(ip)

    except Exception as e:
        print(f"Error reading JSON: {e}")

    return list(ips)

def scan_ports(ip):
    scan=nmap.PortScanner()
    try:
        print(f"Scanning ports for {ip}")
        scan.scan(ip, arguments='-T4 -p-')
        return scan[ip]
    except Exception as e:
        return {"error": str(e)}

def get_ip_and_ports_from_json(domain):
    filepath = f"results/port_analysis_{domain.replace('.', '_')}.json"
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        ip = list(data.keys())[0]
        ports = data[ip].get("tcp", {})

        open_ports = [
            int(port)
            for port, details in ports.items()
            if details.get("state") == "open"
        ]
        
        return ip, open_ports

    except Exception as e:
        print(f"Error reading the file: {e}")
        return None, []




def scan_vulnerabilities(ip, ports):
    port_list = ",".join(map(str, ports))
    try:
        print(f"Scanning for vulnerabilities in {ip} (ports: {port_list})")

        result = subprocess.run(
            ["nmap", "-Pn","-p", port_list, "--script", "vuln", ip],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return {"error": result.stderr}

        return {"output": result.stdout}

    except Exception as e:
        return {"error": str(e)}


def save_port_scan_results(domain):
    filename = f"results/port_analysis_{domain.replace('.', '_')}.json"
    ips = get_ips_from_json(domain)
    results = {}

    for ip in ips:
        port_data = scan_ports(ip)
        results[ip] = port_data
    try:
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[!] Error saving the JSON: {e}")



