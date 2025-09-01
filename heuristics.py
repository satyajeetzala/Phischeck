import re
import socket
import requests
import datetime
import logging
import idna
import tldextract
import dns.resolver
import whois
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup
import base64

# === Logging Setup ===
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# === API KEYS (replace with your real keys) ===
VIRUSTOTAL_API_KEY = '7a9b4a49e805d077543c8bf6efded38b8c47b33392cac4d792aa60106c2f6fb9'
GOOGLE_SAFE_BROWSING_API_KEY = 'AIzaSyBJAeyuEFMVag1CwftEU_nt3ENQoR1sH1A'
ABUSEIPDB_API_KEY = '884b6651c32a444b98778e9930617ca81d9e34a4e6d497feaf36a67b265fbba8c500696a4adf6295'

# === Constants ===
KNOWN_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'cutt.ly', 'rb.gy', 'shorte.st'
}
PHISHING_PHRASES = [
    "enter your password", "sign in to view document", "confirm your identity",
    "verify your account", "secure document", "update billing information",
    "your account has been suspended"
]
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'update', 'account', 'banking', 'ebay', 'paypal'
]

# === Helper Functions ===

def normalize_url(url):
    parsed = urlparse(url, scheme='http')
    if not parsed.netloc:
        parsed = urlparse('http://' + url)
    return urlunparse(parsed)

def extract_domain(url):
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(parsed.netloc)
        domain = f"{ext.domain}.{ext.suffix}"
        return idna.decode(domain)
    except Exception as e:
        logger.warning(f"Failed to extract domain: {e}")
        return ""

def get_all_ip_addresses(domain):
    try:
        results = socket.getaddrinfo(domain, None)
        ip_addresses = set()
        for res in results:
            ip = res[4][0]
            ip_addresses.add(ip)
        return list(ip_addresses)
    except Exception as e:
        logger.warning(f"IP address resolution failed: {e}")
        return [f"Error: {e}"]
    
def uses_ngrok_tunnel(url):
    host = urlparse(url).netloc.lower()
    return host.endswith(".ngrok.app") or host.endswith(".ngrok.io")

def has_ip_address(url):
    ipv4 = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url)
    ipv6 = re.search(r'\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\b', url)
    return bool(ipv4 or ipv6)

def has_suspicious_keywords(url):
    return any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)

def is_shortened_url(domain):
    return domain in KNOWN_SHORTENERS

def has_at_symbol(url):
    return '@' in url

def is_punycode(domain):
    return 'xn--' in domain

def has_many_subdomains(url):
    ext = tldextract.extract(urlparse(url).netloc)
    return ext.subdomain.count('.') >= 1

def has_hyphen(domain):
    return '-' in domain.split('.')[0]

def is_domain_young(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not isinstance(creation_date, datetime.datetime):
            return True
        now = datetime.datetime.now(datetime.timezone.utc)
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)
        age = (now - creation_date).days
        return age < 120
    except Exception as e:
        logger.warning(f"WHOIS check failed: {e}")
        return True

def has_dns_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return bool(answers)
    except Exception:
        return False

def contains_phishy_html(html):
    try:
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text().lower()
        return any(phrase in text for phrase in PHISHING_PHRASES)
    except Exception as e:
        logger.warning(f"HTML parsing failed: {e}")
        return False

def url_redirects_to_suspicious_domain(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        final_domain = extract_domain(response.url)
        if final_domain != extract_domain(url) and has_suspicious_keywords(response.url):
            logger.info("URL redirects to suspicious domain.")
            return True
    except Exception as e:
        logger.warning(f"Redirect check failed: {e}")
    return False

# === VirusTotal API ===

def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return None
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=5)
    except Exception:
        pass
    try:
        resp = requests.get(report_url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0)
            }
    except Exception:
        pass
    return None

# === Google Safe Browsing API ===

def check_google_safe_browsing(url):
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return None
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "yourcompany",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    params = {'key': GOOGLE_SAFE_BROWSING_API_KEY}
    try:
        resp = requests.post(endpoint, params=params, json=payload, timeout=5)
        if resp.status_code == 200:
            matches = resp.json().get('matches', [])
            return len(matches) > 0
    except Exception:
        pass
    return False

# === OpenPhish Integration ===

def fetch_openphish_feed():
    url = "https://openphish.com/feed.txt"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return set(response.text.splitlines())
    except Exception:
        pass
    return set()

def check_openphish(url, openphish_feed):
    return url in openphish_feed

# === AbuseIPDB API ===

def check_abuseipdb(domain):
    if not ABUSEIPDB_API_KEY:
        return None
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return None
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    try:
        resp = requests.get(endpoint, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            score = data['data']['abuseConfidenceScore']
            return score
    except Exception:
        pass
    return None

# === Main Scoring Function (Detailed Output) ===

def calculate_phishing_score(url, openphish_feed=None):
    score = 0
    url = normalize_url(url)
    domain = extract_domain(url)
    html = ""

    # --- IP Address Resolution (for display) ---
    ip_addresses = get_all_ip_addresses(domain)

    try:
        headers = {"User-Agent": "Mozilla/5.0 (PhishDetectorBot)"}
        response = requests.get(url, headers=headers, timeout=5, verify=True, allow_redirects=True)
        html = response.text
    except requests.RequestException as e:
        logger.warning(f"Failed to fetch HTML: {e}")

    # Heuristics with weighted scores
    heuristics_results = {
        'has_ip_address': has_ip_address(url),
        'has_suspicious_keywords': has_suspicious_keywords(url),
        'is_shortened_url': is_shortened_url(domain),
        'has_at_symbol': has_at_symbol(url),
        'is_punycode': is_punycode(domain),
        'has_many_subdomains': has_many_subdomains(url),
        'has_hyphen': has_hyphen(domain),
        'is_domain_young': is_domain_young(domain),
        'has_dns_record': has_dns_record(domain),
        'contains_phishy_html': contains_phishy_html(html),
        'url_redirects_to_suspicious_domain': url_redirects_to_suspicious_domain(url)
    }

    # Weighted scoring (adjust as needed)
    if heuristics_results['has_ip_address']:
        score += 2
    if heuristics_results['has_suspicious_keywords']:
        score += 1
    if heuristics_results['is_shortened_url']:
        score += 2
    if uses_ngrok_tunnel(url):
        score += 1  # or consider automatic flagging
    if heuristics_results['has_at_symbol']:
        score += 1
    if heuristics_results['is_punycode']:
        score += 1
    if heuristics_results['has_many_subdomains']:
        score += 1
    if heuristics_results['has_hyphen']:
        score += 1
    if heuristics_results['is_domain_young']:
        score += 2
    if not heuristics_results['has_dns_record']:
        score += 2
    if heuristics_results['contains_phishy_html']:
        score += 2
    if heuristics_results['url_redirects_to_suspicious_domain']:
        score += 2

    # External API checks
    vt_result = check_virustotal(url)
    gsafebrowsing = check_google_safe_browsing(url)
    openphish_detected = False
    if openphish_feed is not None:
        openphish_detected = check_openphish(url, openphish_feed)
    abuse_score = check_abuseipdb(domain)

    # === External tool override logic ===
    external_flag = False
    external_reason = []

    if vt_result and (vt_result.get('malicious', 0) > 0 or vt_result.get('suspicious', 0) > 0):
        external_flag = True
        external_reason.append("VirusTotal flagged as malicious/suspicious")
    if gsafebrowsing:
        external_flag = True
        external_reason.append("Google Safe Browsing flagged")
    if openphish_detected:
        external_flag = True
        external_reason.append("OpenPhish listed")
    if abuse_score is not None and abuse_score >= 50:
        external_flag = True
        external_reason.append(f"AbuseIPDB score {abuse_score}")

    if external_flag:
        is_phishing = True
        phishing_reason = "Flagged by: " + ", ".join(external_reason)
    else:
        is_phishing = score >= 2
        phishing_reason = "Heuristic score threshold" if is_phishing else "No threat detected"

    details = {
        'ip_addresses': ip_addresses,
        'heuristics': heuristics_results,
        'virustotal': vt_result,
        'google_safe_browsing': gsafebrowsing,
        'openphish': openphish_detected,
        'abuseipdb_score': abuse_score,
        'phishing_reason': phishing_reason
    }

    return {
        'score': score,
        'is_phishing': is_phishing,
        'details': details
    }

# === Example usage ===
if __name__ == "__main__":
    test_url = "http://example.com"
    openphish_feed = fetch_openphish_feed()
    result = calculate_phishing_score(test_url, openphish_feed=openphish_feed)

    print("========== Phishing Detection Report ==========")
    print(f"URL: {test_url}")
    print(f"Phishing Score: {result['score']}")
    print(f"Phishing Verdict: {'Phishing' if result['is_phishing'] else 'Safe'}")
    print(f"Reason: {result['details'].get('phishing_reason', '')}\n")

    print("--- Domain IP Addresses ---")
    for ip in result['details']['ip_addresses']:
        print(ip)

    print("\n--- Heuristics Breakdown ---")
    for k, v in result['details']['heuristics'].items():
        print(f"{k.replace('_', ' ').capitalize()}: {'Yes' if v else 'No'}")

    print("\n--- External Service Results ---")
    vt = result['details']['virustotal']
    print(f"VirusTotal result: {vt if vt is not None else 'Not checked'}")
    gs = result['details']['google_safe_browsing']
    print(f"Google Safe Browsing result: {'Flagged' if gs else 'Not flagged'}")
    op = result['details']['openphish']
    print(f"OpenPhish detection: {'Listed' if op else 'Not listed'}")
    abuse = result['details']['abuseipdb_score']
    print(f"AbuseIPDB score: {abuse if abuse is not None else 'N/A'}")
