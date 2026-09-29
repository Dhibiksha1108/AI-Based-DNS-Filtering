import os
import pandas as pd

def inspect():
    data_dir = "data"
    print("=== 1. Dataset Files & Sizes ===")
    files = [f for f in os.listdir(data_dir) if os.path.isfile(os.path.join(data_dir, f))]
    for fname in files:
        fpath = os.path.join(data_dir, fname)
        size_bytes = os.path.getsize(fpath)
        size_mb = size_bytes / (1024 * 1024)
        print(f"File: {fname} | Format: {fname.split('.')[-1].upper()} | Size: {size_mb:.2f} MB ({size_bytes} bytes)")

    main_csv = os.path.join(data_dir, "dns_threats_dataset.csv")
    print("\n=== 2. Dataset Dimensions & Inspection (dns_threats_dataset.csv) ===")
    df = pd.read_csv(main_csv)
    print(f"Rows: {df.shape[0]}, Columns: {df.shape[1]}")
    print("Column Names:", list(df.columns))

    print("\n=== 3. Target Classes Distribution ===")
    if 'class_name' in df.columns:
        print(df['class_name'].value_counts())
    print("\nRaw Labels Distribution:")
    print(df['label'].value_counts().head(10))

    print("\n=== 4. Data Quality Check ===")
    print("Missing Values per Column:")
    print(df.isnull().sum())
    print(f"Duplicate Rows Count: {df.duplicated().sum()}")

    print("\n=== 5. Real Sample Rows ===")
    print(df.sample(5, random_state=42)[['domain', 'label', 'class_name']])

if __name__ == "__main__":
    inspect()
