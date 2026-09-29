import os
import pandas as pd
import numpy as np
from src.feature_extraction import extract_features_dataframe

def process_features():
    input_file = os.path.join("data", "dns_threats_dataset.csv")
    output_file = os.path.join("data", "dns_threats_features.csv")
    
    print(f"1. Loading dataset from {input_file}...")
    df = pd.read_csv(input_file)
    print(f"Original dataset shape: {df.shape}")
    
    print("\n2. Extracting lexical features...")
    processed_df = extract_features_dataframe(df, domain_column='domain')
    print(f"Processed dataset shape: {processed_df.shape}")
    
    print("\n3. Column Names:")
    print(processed_df.columns.tolist())
    
    print("\n4. Checking for missing values:")
    null_counts = processed_df.isnull().sum()
    print(null_counts)
    assert null_counts.sum() == 0, "Error: Missing values found!"
    
    print("\n5. Checking for infinite values in numerical features:")
    num_cols = processed_df.select_dtypes(include=[np.number]).columns
    inf_counts = np.isinf(processed_df[num_cols]).sum()
    print(inf_counts)
    assert inf_counts.sum() == 0, "Error: Infinite values found!"
    
    print("\n6. Saving processed dataset to", output_file)
    processed_df.to_csv(output_file, index=False)
    print("Saved successfully!")
    
    print("\n7. Basic Statistics for Numerical Features:")
    print(processed_df[num_cols].describe().T[['mean', 'std', 'min', '50%', 'max']])
    
    print("\n8. First 10 Processed Rows:")
    print(processed_df.head(10))

if __name__ == "__main__":
    process_features()
