import imaplib
import email
from email.header import decode_header
import re
import datetime
import tldextract
import whois
from bs4 import BeautifulSoup

# Phishing detection function
def check_url(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    try:
        domain_info = whois.whois(domain)
        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date

        if creation_date and (datetime.datetime.now() - creation_date).days < 180:
            return True
    except Exception as e:
        print(f"Error checking WHOIS for {domain}: {e}")

    if re.search(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', extracted.domain):
        return True

    phishing_keywords = ["banking", "login", "not a scam", "banking secure", "urgent", "verification required"]
    if any(keyword in url for keyword in phishing_keywords):
        return True

    return False

# Function to process email content and check for phishing URLs
def scan_for_phishing(content_type, body):
    phishing_detected = False
    if 'text/html' in content_type:
        soup = BeautifulSoup(body, 'html.parser')
        urls = [link.get('href') for link in soup.find_all('a')]
    else:
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)

    for url in urls:
        if url and check_url(url):
            print(f"Phishing URL detected: {url}")
            phishing_detected = True

    return phishing_detected

# Function to connect to the Gmail server and scan for phishing URLs
def connect_and_scan(username, password, server='imap.gmail.com'):
    # Connect to the IMAP server
    mail = imaplib.IMAP4_SSL(server)
    mail.login(username, password)
    mail.select("inbox")  # Connect to inbox.

    status, messages = mail.search(None, 'ALL')
    for num in messages[0].split():
        typ, data = mail.fetch(num, '(RFC822)')
        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject = decode_header(msg['subject'])[0][0]
                if isinstance(subject, bytes):
                    subject = subject.decode()
                from_ = msg.get('from')
                print('From:', from_)
                print('Subject:', subject)

                phishing_detected = False

                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))
                        try:
                            body = part.get_payload(decode=True).decode()
                        except:
                            continue
                        if "text/plain" in content_type and "attachment" not in content_disposition:
                            phishing_detected = scan_for_phishing(content_type, body) or phishing_detected
                        elif "text/html" in content_type:
                            phishing_detected = scan_for_phishing(content_type, body) or phishing_detected
                else:
                    content_type = msg.get_content_type()
                    body = msg.get_payload(decode=True).decode()
                    phishing_detected = scan_for_phishing(content_type, body)

                if not phishing_detected:
                    print("No phishing URLs detected in this email.")
                print("="*100)

    mail.logout()

# Replace 'your_username' and 'your_password' with your email login credentials
connect_and_scan('*email*', '*password*')
