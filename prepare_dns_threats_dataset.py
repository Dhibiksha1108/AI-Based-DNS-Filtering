import os
import pandas as pd
import numpy as np

def prepare_dataset():
    os.makedirs("data", exist_ok=True)
    
    print("Loading Benign and DGA domains from public dataset (harpomaxx/dga-detection)...")
    val_parquet_url = 'https://huggingface.co/datasets/harpomaxx/dga-detection/resolve/refs%2Fconvert%2Fparquet/default/validation/0000.parquet'
    hf_df = pd.read_parquet(val_parquet_url)
    
    # Extract Benign domains (normal.bambenek)
    benign_df = hf_df[hf_df['label'] == 'normal.bambenek'].copy()
    benign_df['class_name'] = 'Benign'
    
    # Extract DGA domains
    dga_df = hf_df[hf_df['label'].str.startswith('dga.')].copy().head(5000)
    dga_df['class_name'] = 'DGA'
    
    # Generate authentic DNS Tunnelling query domains based on standard tools (dnscat2, iodine, dnsExfiltrator)
    print("Preparing DNS Tunnelling domain queries (dnscat2, iodine, dnsExfiltrator)...")
    np.random.seed(42)
    hex_chars = list("0123456789abcdef")
    base32_chars = list("abcdefghijklmnopqrstuvwxyz234567")
    
    tunnel_domains = []
    # dnscat2 style: <hex_payload>.dnscat2.target.org
    for i in range(1500):
        payload = "".join(np.random.choice(hex_chars, size=np.random.randint(16, 40)))
        tunnel_domains.append(f"dnscat.{payload}.tunnel-domain.net")
        
    # iodine style: <base32_payload>.iodine.target.com
    for i in range(1500):
        payload = "".join(np.random.choice(base32_chars, size=np.random.randint(20, 50)))
        tunnel_domains.append(f"v1.{payload}.iodine-server.org")
        
    # dnsExfiltrator style: <hex_payload>.exfiltrator.io
    for i in range(1000):
        payload = "".join(np.random.choice(hex_chars, size=np.random.randint(24, 48)))
        tunnel_domains.append(f"{payload}.exfiltrate-data.io")

    tunnel_df = pd.DataFrame({
        'domain': tunnel_domains,
        'label': 'dns_tunnelling',
        'class': 2,
        'class_name': 'DNS Tunnelling'
    })
    
    # Combine into a unified multiclass dataset
    combined_df = pd.concat([benign_df, dga_df, tunnel_df], ignore_index=True)
    
    # Save original combined CSV and train/test splits into data/ folder
    combined_path = os.path.join("data", "dns_threats_dataset.csv")
    train_path = os.path.join("data", "train_combined_multiclass.csv")
    test_path = os.path.join("data", "test_combined_multiclass.csv")
    
    combined_df.to_csv(combined_path, index=False)
    
    # Create 80-20 train/test split preserving original data
    train_df = combined_df.sample(frac=0.8, random_state=42)
    test_df = combined_df.drop(train_df.index)
    
    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)
    
    print("Dataset prepared successfully in data/ directory!")

if __name__ == "__main__":
    prepare_dataset()
