import cloudscraper
import os

scraper = cloudscraper.create_scraper(
    browser={
        'browser': 'chrome',
        'platform': 'windows',
        'desktop': True
    }
)
os.makedirs("data", exist_ok=True)

urls = [
    ("train_combined_multiclass.csv.gz", "https://zenodo.org/records/6508640/files/train_combined_multiclass.csv.gz?download=1"),
    ("test_combined_multiclass.csv.gz", "https://zenodo.org/records/6508640/files/test_combined_multiclass.csv.gz?download=1")
]

for filename, url in urls:
    filepath = os.path.join("data", filename)
    print(f"Downloading {filename}...")
    res = scraper.get(url, stream=True)
    res.raise_for_status()
    with open(filepath, 'wb') as f:
        for chunk in res.iter_content(chunk_size=65536):
            if chunk:
                f.write(chunk)
    size_mb = os.path.getsize(filepath) / (1024 * 1024)
    print(f"Saved {filename}: {size_mb:.2f} MB ({os.path.getsize(filepath)} bytes)")
