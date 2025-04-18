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


domain_objective="openai.com"
obtain_whois(domain_objective)

