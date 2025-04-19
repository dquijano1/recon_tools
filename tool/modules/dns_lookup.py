import dns.resolver
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed 
import time

dns_servers = [
    "8.8.8.8", "8.8.4.4",              # Google
    "76.76.2.0", "76.76.10.0",         # Control D
    "9.9.9.9", "149.112.112.112",      # Quad9
    "208.67.222.222", "208.67.220.220",# OpenDNS
    "1.1.1.1", "1.0.0.1",              # Cloudflare
    "94.140.14.14", "94.140.15.15",    # AdGuard
    "185.228.168.9", "185.228.169.9",  # CleanBrowsing
    "76.76.19.19", "76.223.122.150"    # Alternate DNS
    ]
def get_dns_records(domain):
    #empty dictionary for future json
    results = {record: {} for record in ["A", "AAAA", "MX", "NS", "TXT"] }
    pool_task=[]

    print(f"\n🔎 DNS Lookup for {domain}")
    with ThreadPoolExecutor(max_workers=10) as pool_executor:
        for record_type in results:
            for dns_ip in dns_servers:
                pool_task.append(pool_executor.submit(fetch_dns, domain, record_type, dns_ip))
        for pool_result in as_completed(pool_task):
            record_type, dns_ip, values= pool_result.result()
            results[record_type][dns_ip]=values
    return results

def fetch_dns(domain, record_type, dns_ip):
    resolver= dns.resolver.Resolver()
    resolver.nameservers= [dns_ip]
    try:
        answer= resolver.resolve(domain, record_type, lifetime=10)
        values= [rdata.to_text() for rdata in answer]

        if record_type in ["A", "AAAA"]:
            geo_location_info=[]
            for ip in values:
                ip_info= get_ip_info(ip)
                geo_location_info.append({
                    "ip": ip,
                    "location": ip_info
                })
            return (record_type, dns_ip, geo_location_info)
        else:
            return (record_type, dns_ip, values)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return (record_type, dns_ip, [])
    except Exception as e:
        return (record_type, dns_ip, [])

def get_ip_info(ip):
    try:
        url = f"https://ipwho.is/{ip}"
        response = requests.get(url)
        time.sleep(1)
        data = response.json()

        if data["success"]: 
            return {
                "country": data["country"],
                "region": data["region"],
                "city": data["city"],
                "org": data["connection"]["org"],
                "isp": data["connection"]["isp"]
            }
        else:
            return {"ip": ip, "error": data.get("message", "Unknown error")}
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def dns_to_json(domain, dns_data):
    filepath=f"results/{domain.replace('.','_')}.json"
    try:
        #open the file we previously created inside WHOIS
        with open(filepath, 'r') as f:
            data= json.load(f)
            #add the data into the new key
            data['dns_lookup']=dns_data
        #write the new data into the file
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error updating the json {e}")

dns_to_json("superette.com.mx",get_dns_records("superette.com.mx"))