import whois
from datetime import datetime, timezone
from dateutil import parser
import os
import json

def obtain_whois(domain):
    print(f"Obtaining ❓WHOIS❓ for {domain}")
    results={"whois":{}}
    try:
        w= whois.whois(domain)
        for key, value in w.items():
            if isinstance(value,(list,datetime)):
                results["whois"][key]=str(value)
            else:
                results["whois"][key]=value
            if key =="creation_date":
                creation_analysis=domain_is_recent(value)
                if creation_analysis:
                    results["whois"]["domain_age"]=creation_analysis
        return results     
    except Exception as e:
        print(f"Error obtaining WHOIS for {domain}")
        print(e)

# check if the creation date of the domain for WHOIS is less than the selected threshold 
# if true could possibly be a malicious domain.
# @params: creation_date: string or datetime object
#          minimum_creation: this number can be changed depending of the needs of each user.
def domain_is_recent(creation_date, minimum_creation=30):
    try:
        #verify if the creation date is a datetime object
        if not isinstance(creation_date, datetime):
            creation_date=parser.parser(str(creation_date))
        
        if creation_date.tzinfo is None:
            creation_date= creation_date.replace(tzinfo=timezone.utc)
        #get current date of the system
        current_date= datetime.now(timezone.utc)
        difference=current_date-creation_date
        difference=difference.days

        #if the difference is less than the threshold we set then could be a phishing domain
        return {
            "day_since_creation": difference,
            "is_suspicious": difference< minimum_creation
        }
        
    except Exception as e:
        print(f"Error processing {creation_date}")

def whois_to_json(domain, data):
    os.makedirs("results", exist_ok=True)
    filename=f"results/{domain.replace('.','_')}.json"
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"WHOIS saved to {filename}")

whois_to_json("openai.com", obtain_whois("openai.com"))
