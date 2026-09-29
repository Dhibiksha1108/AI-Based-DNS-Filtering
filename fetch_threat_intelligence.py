import os
import requests

FEED_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"
TI_DIR = os.path.join("data", "threat_intelligence")
ORIGINAL_FEED_FILE = os.path.join(TI_DIR, "urlhaus_hosts.txt")
PROCESSED_DOMAINS_FILE = os.path.join(TI_DIR, "urlhaus_domains.txt")

def download_and_parse_threat_feed():
    os.makedirs(TI_DIR, exist_ok=True)
    print(f"1. Downloading official URLhaus threat feed from {FEED_URL}...")
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    response = requests.get(FEED_URL, headers=headers, timeout=30)
    response.raise_for_status()
    
    # Preserve original downloaded feed
    with open(ORIGINAL_FEED_FILE, "w", encoding="utf-8") as f:
        f.write(response.text)
    
    original_size = os.path.getsize(ORIGINAL_FEED_FILE)
    print(f"Saved original feed to {ORIGINAL_FEED_FILE} ({original_size / 1024:.2f} KB)")
    
    # Parse domain indicators (lines formatted as: 127.0.0.1 <domain>)
    domains = set()
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            ip, domain = parts[0], parts[1]
            if domain and domain not in ("127.0.0.1", "localhost"):
                domains.add(domain.lower().strip('.'))
                
    # Save processed domain list for fast lookup
    with open(PROCESSED_DOMAINS_FILE, "w", encoding="utf-8") as f:
        for domain in sorted(domains):
            f.write(f"{domain}\n")
            
    print(f"Parsed {len(domains)} unique malicious domains saved to {PROCESSED_DOMAINS_FILE}")
    return len(domains)

if __name__ == "__main__":
    download_and_parse_threat_feed()
