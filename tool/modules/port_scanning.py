import json
import nmap

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


save_port_scan_results("superette.com.mx",)
