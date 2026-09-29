"""
DNS Threat Intelligence & Machine Learning
Module: Feature Extraction

This module provides modular functions to extract lexical and statistical features
from DNS domain name strings for threat classification (Benign, DGA, DNS Tunnelling).
"""

import math
from collections import Counter
import pandas as pd
import numpy as np


def calculate_entropy(text: str) -> float:
    """
    Calculate the Shannon Entropy of a given string.
    Higher entropy indicates higher randomness in character distribution.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features_from_domain(domain_str: str) -> dict:
    """
    Extract lexical features from a single domain string.
    Returns a dictionary of numerical features suitable for ML models or single domain evaluation.
    """
    if not isinstance(domain_str, str):
        domain_str = str(domain_str) if domain_str is not None else ""

    domain_len = len(domain_str)
    if domain_len == 0:
        return {
            'domain_length': 0,
            'number_of_digits': 0,
            'digit_ratio': 0.0,
            'number_of_letters': 0,
            'number_of_special_characters': 0,
            'number_of_subdomains': 0,
            'vowel_count': 0,
            'consonant_count': 0,
            'vowel_ratio': 0.0,
            'consonant_ratio': 0.0,
            'unique_character_count': 0,
            'character_entropy': 0.0
        }

    domain_lower = domain_str.lower()
    vowels_set = set('aeiou')

    digits = sum(c.isdigit() for c in domain_str)
    letters = sum(c.isalpha() for c in domain_str)
    special_chars = sum(not c.isalnum() for c in domain_str)
    subdomains = domain_str.count('.')

    vowels = sum(c in vowels_set for c in domain_lower)
    consonants = sum(c.isalpha() and c not in vowels_set for c in domain_lower)

    digit_ratio = round(digits / domain_len, 4)
    vowel_ratio = round(vowels / domain_len, 4)
    consonant_ratio = round(consonants / domain_len, 4)
    unique_chars = len(set(domain_str))
    entropy = calculate_entropy(domain_str)

    return {
        'domain_length': domain_len,
        'number_of_digits': digits,
        'digit_ratio': digit_ratio,
        'number_of_letters': letters,
        'number_of_special_characters': special_chars,
        'number_of_subdomains': subdomains,
        'vowel_count': vowels,
        'consonant_count': consonants,
        'vowel_ratio': vowel_ratio,
        'consonant_ratio': consonant_ratio,
        'unique_character_count': unique_chars,
        'character_entropy': entropy
    }


def extract_features_dataframe(df: pd.DataFrame, domain_column: str = 'domain') -> pd.DataFrame:
    """
    Extract features for an entire pandas DataFrame containing a domain column.
    Preserves all original columns and appends extracted numerical features.
    """
    if domain_column not in df.columns:
        raise ValueError(f"Column '{domain_column}' not found in DataFrame.")

    features_list = df[domain_column].apply(extract_features_from_domain).tolist()
    features_df = pd.DataFrame(features_list)

    # Concatenate original dataframe with extracted features dataframe
    result_df = pd.concat([df.reset_index(drop=True), features_df.reset_index(drop=True)], axis=1)
    return result_df


if __name__ == "__main__":
    # Quick self-test for single domain feature extraction
    sample_domain = "dnscat.0a1b2c3d4e5f.tunnel-domain.net"
    print(f"Sample domain: {sample_domain}")
    print("Extracted Features:")
    for k, v in extract_features_from_domain(sample_domain).items():
        print(f"  {k}: {v}")
