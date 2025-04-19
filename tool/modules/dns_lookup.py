import dns.resolver
import json
import requests

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
    results = {}
    #list of records we are resolving
    records = ["A", "AAAA", "MX", "NS", "TXT"]

    print(f"\n🔎 DNS Lookup for {domain}")
    for record_type in records:
        results[record_type] = {}  # Initialize dict for each type
        #create resolver for each dns server
        for dns_ip in dns_servers:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_ip]
            try:
                #get answer for specific record type, lifetime can be changed if needed
                answer = resolver.resolve(domain, record_type, lifetime=5)
                values = []
                for rdata in answer:
                    value = rdata.to_text()
                    #add record info into a list
                    values.append(value)
                if record_type in ["A", "AAAA"]:
                    geo=[]
                    for value in values:
                        ip_info=get_ip_info(value)
                        geo.append({
                            "ip": value,
                            "location": ip_info
                        })
                    results[record_type][dns_ip]=geo
                else:
                    # Save values to the specific record and specific dns server we are using
                    results[record_type][dns_ip] = values
            #if resolver doesnt get an answer or get an eror we set that value to an empty list
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                results[record_type][dns_ip] = []
                continue
            except Exception as e:
                results[record_type][dns_ip] = []
                continue
    return results

def get_ip_info(ip):
    try:
        url = f"https://ipwho.is/{ip}"
        response = requests.get(url)
        data = response.json()

        if data["success"]: 
            return {
                "ip": ip,
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

dns_to_json("facebook.com",get_dns_records("facebook.com"))