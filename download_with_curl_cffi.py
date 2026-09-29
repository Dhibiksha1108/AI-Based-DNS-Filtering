from curl_cffi import requests
import os
import time

os.makedirs("data", exist_ok=True)

urls = [
    ("train_combined_multiclass.csv.gz", "https://zenodo.org/records/6508640/files/train_combined_multiclass.csv.gz?download=1"),
    ("test_combined_multiclass.csv.gz", "https://zenodo.org/records/6508640/files/test_combined_multiclass.csv.gz?download=1")
]

print("Starting download via curl_cffi impersonating Chrome with 300s timeout...")

for filename, url in urls:
    filepath = os.path.join("data", filename)
    print(f"Downloading {filename} from {url}...")
    success = False
    for attempt in range(1, 4):
        try:
            print(f"Attempt {attempt} for {filename}...")
            res = requests.get(url, impersonate="chrome", stream=True, timeout=300)
            print(f"HTTP Status: {res.status_code}")
            if res.status_code == 200:
                with open(filepath, 'wb') as f:
                    downloaded = 0
                    for chunk in res.iter_content(chunk_size=131072):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                size_mb = os.path.getsize(filepath) / (1024 * 1024)
                print(f"Successfully downloaded {filename}: {size_mb:.2f} MB ({os.path.getsize(filepath)} bytes)")
                success = True
                break
            else:
                print(f"HTTP {res.status_code}: {res.text[:200]}")
        except Exception as e:
            print(f"Error on attempt {attempt}: {e}")
            time.sleep(3)
    if not success:
        print(f"Failed to download {filename} after 3 attempts.")
