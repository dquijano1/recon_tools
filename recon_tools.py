import whois
from datetime import datetime, timezone
import dns.resolver

### WHOIS SECTION ###

def obtain_whois(domain):
    print(f"Obtaining ❓WHOIS❓ for {domain}")
    try:
        w= whois.whois(domain)
        for key, value in w.items():
            print(f"{key}: {value}")
            if key =="creation_date":
                domain_is_recent(value[1])
    except Exception as e:
        print(f"Error obtaining WHOIS for {domain}")

# check if the creation date of the domain for WHOIS is less than the selected threshold 
# if true could possibly be a malicious domain.
# @params: creation_date: string or datetime object
#          minimum_creation: this number can be changed depending of the needs of each user.
def domain_is_recent(creation_date, minimum_creation=30):
    try:
        #verify if the creation date is a datetime object
        if not isinstance(creation_date, datetime):
            print(f"Error: date must be a datetime object.")
            return
        #get current date of the system
        current_date= datetime.now(timezone.utc)
        difference=current_date-creation_date
        difference=difference.days

        #if the difference is less than the threshold we set then could be a phishing domain
        if difference< minimum_creation:
            print(f"Domain was created {difference} days ago. Could be sus!!")
        else:
            print(f"Domain was created {difference} days ago. This is not sus :)")
        
    except Exception as e:
        print(f"Error processing {creation_date}")

### DNS section ###
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
    records = ["A", "AAAA", "MX", "NS", "TXT"]

    print(f"\n🔎 DNS Lookup for {domain}")
    for record_type in records:
        resolved = False  # Flag to check if some dns already resolved
        for dns_ip in dns_servers:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_ip]
            try:
                answer = resolver.resolve(domain, record_type, lifetime=5)
                print(f"{record_type} Record (via {dns_ip}):")
                for rdata in answer:
                    print(f"  {rdata.to_text()}")
                resolved = True
                break  # exit the loop if DNS was successfull
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except Exception as e:
                continue
        if not resolved:
            print(f"{record_type} Records: Not found or not available.")

domain_objective="openai.com"
obtain_whois(domain_objective)
get_dns_records(domain_objective)
