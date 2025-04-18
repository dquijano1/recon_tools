import dns.resolver

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