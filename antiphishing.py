import tldextract
import whois
import re
import datetime

def check_url(url):
    try:
        # Extract domain details
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        # Perform a WHOIS lookup to find the registration date
        domain_info = whois.whois(domain)
        if 'creation_date' in domain_info and type(domain_info.creation_date) is list:
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date

        # Initialize phishing risk flag
        phishing_risk = False

        # Heuristic checks
        # Check if the domain was recently registered
        if creation_date and (datetime.datetime.now() - creation_date).days < 180:
            print(f"Warning: {domain} was recently registered. Potential phishing risk.")
            phishing_risk = True

        # Check for IP address in URL (common in phishing attacks)
        if re.search(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', extracted.domain):
            print("Warning: URL contains an IP address, potential phishing risk.")
            phishing_risk = True

        # Check for misleading domain name
        known_phishing_keywords = ["login", "verify", "account", "banking", "secure", "update"]
        if any(keyword in url for keyword in known_phishing_keywords):
            print("Warning: URL contains keywords commonly used in phishing.")
            phishing_risk = True

        # Additional checks can be added here (e.g., checking against known bad URLs)

        if not phishing_risk:
            print(f"{url} appears to be a legitimate URL.")

    except Exception as e:
        print(f"Error checking URL {url}: {str(e)}")

# Prompt for user input
while True:
    url = input("Enter a URL to check (or type 'exit' to quit): ").strip()
    if url.lower() == 'exit':
        break
    check_url(url)

# Example usage
#check_url("https://www.jpmorganchase.com")
#check_url("https://secure-login-verification.netlify.app")
#check_url("https://192.168.1.1")
