import os
import requests

PCAP_DIR = os.path.join("data", "pcap")
PCAP_FILE = os.path.join(PCAP_DIR, "sample_dns.pcap")

# Legitimate public sample DNS PCAP from Scapy / Wireshark official repositories
PCAP_URLS = [
    "https://raw.githubusercontent.com/seladb/PcapPlusPlus/master/Tests/PcapExamples/dns.pcap",
    "https://raw.githubusercontent.com/kholia/malware-pcaps/master/dns.pcap"
]

def download_sample_pcap():
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"1. Downloading official sample DNS PCAP file to {PCAP_FILE}...")
    
    headers = {'User-Agent': 'Mozilla/5.0'}
    for url in PCAP_URLS:
        try:
            print(f"Attempting download from {url}...")
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code == 200 and len(r.content) > 100:
                with open(PCAP_FILE, "wb") as f:
                    f.write(r.content)
                size = os.path.getsize(PCAP_FILE)
                print(f"Successfully downloaded {PCAP_FILE}: {size / 1024:.2f} KB ({size} bytes)")
                return PCAP_FILE
        except Exception as e:
            print(f"Failed from {url}: {e}")
            
    raise RuntimeError("Failed to download sample PCAP from all public sources.")

if __name__ == "__main__":
    download_sample_pcap()
