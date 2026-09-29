import os
import requests

PCAP_DIR = os.path.join("data", "pcap")
PCAP_FILE = os.path.join(PCAP_DIR, "sample_dns.pcap")
PCAP_URL = "https://raw.githubusercontent.com/ggyggy666/DNS-Tunnel-Datasets/master/tunnel/tuns.pcap"

def download_pcap():
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"Downloading official DNS PCAP dataset from {PCAP_URL}...")
    r = requests.get(PCAP_URL, stream=True, timeout=60)
    r.raise_for_status()
    with open(PCAP_FILE, "wb") as f:
        for chunk in r.iter_content(chunk_size=65536):
            if chunk:
                f.write(chunk)
    size_mb = os.path.getsize(PCAP_FILE) / (1024 * 1024)
    print(f"Successfully downloaded {PCAP_FILE}: {size_mb:.2f} MB ({os.path.getsize(PCAP_FILE)} bytes)")

if __name__ == "__main__":
    download_pcap()
