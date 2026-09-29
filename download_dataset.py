import os
import re
import requests

def download_file(session, url, target_path):
    print(f"Downloading from {url} to {target_path}...")
    with session.get(url, stream=True) as r:
        r.raise_for_status()
        with open(target_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    size = os.path.getsize(target_path)
    print(f"Downloaded {target_path} - Size: {size / (1024*1024):.2f} MB ({size} bytes)")

def main():
    os.makedirs("data", exist_ok=True)
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    })

    record_url = "https://zenodo.org/records/6508640"
    print(f"Fetching record page: {record_url}")
    res = session.get(record_url)
    res.raise_for_status()

    # Extract download links from Zenodo record HTML
    # Zenodo file links typically look like: /records/6508640/files/train_combined_multiclass.csv.gz?download=1
    pattern = r'/records/6508640/files/([a-zA-Z0-9_\-\.]+)(?:\?download=1)?'
    matches = set(re.findall(pattern, res.text))
    print(f"Discovered files in record: {matches}")

    files_to_download = [
        'train_combined_multiclass.csv.gz',
        'test_combined_multiclass.csv.gz'
    ]

    for fname in files_to_download:
        file_url = f"https://zenodo.org/records/6508640/files/{fname}?download=1"
        target_path = os.path.join("data", fname)
        download_file(session, file_url, target_path)

if __name__ == "__main__":
    main()
