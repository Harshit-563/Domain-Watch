import pandas as pd
import numpy as np
import math
from collections import Counter
from urllib.parse import urlparse

def calculate_entropy(text):
    if not text or not isinstance(text, str):
        return 0
    counts = Counter(text)
    probs = [count / len(text) for count in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def calculate_digit_ratio(text):
    if not text or not isinstance(text, str):
        return 0
    digits = sum(c.isdigit() for c in text)
    return digits / len(text)

def generate_dns_dataset():
    print("Loading files...")
    
    # 1. Load Benign (OpenDNS)
    try:
        with open('opendns-top-domains.txt', 'r') as f:
            top_benign = [line.strip() for line in f if line.strip()]
        with open('opendns-random-domains.txt', 'r') as f:
            random_benign = [line.strip() for line in f if line.strip()]
        all_benign = list(set(top_benign + random_benign))
    except FileNotFoundError:
        print("Error: Benign text files not found.")
        return

    # 2. Load DGA
    try:
        dga_df = pd.read_csv('dga_websites.csv')
        all_dga = dga_df['domain'].astype(str).tolist()
    except Exception as e:
        print(f"Error loading DGA file: {e}")
        return

    # 3. Load Abuse.ch Malicious
    try:
        abuse_df = pd.read_csv('csv.txt', comment='#', skipinitialspace=True, header=None)
        mal_urls = abuse_df.iloc[:, 2].astype(str).unique().tolist()
        malicious_from_abuse = []
        for url in mal_urls:
            domain = urlparse(url).netloc
            if not domain: domain = url.split('/')[0]
            if domain: malicious_from_abuse.append(domain)
        malicious_from_abuse = list(set(malicious_from_abuse))
    except Exception as e:
        print(f"Error loading Abuse.ch file: {e}")
        return

    print(f"Processing {len(all_benign)} benign and {len(malicious_from_abuse)} malicious domains...")

    data = []

    # Process Labels
    # Label 0: Benign
    for d in all_benign:
        data.append([len(d), calculate_entropy(d), calculate_digit_ratio(d), d.count('.'), 
                     np.random.randint(600, 3601), np.random.randint(1, 4), round(np.random.uniform(1, 6), 2), 0])

    # Label 1: DGA (Sampled to match benign count)
    sampled_dga = np.random.choice(all_dga, min(len(all_benign), len(all_dga)), replace=False)
    for d in sampled_dga:
        if '.' not in d: d += ".net"
        data.append([len(d), calculate_entropy(d), calculate_digit_ratio(d), d.count('.'), 
                     np.random.randint(60, 301), np.random.randint(1, 6), round(np.random.uniform(6, 13), 2), 1])

    # Label 2 & 3: Malicious (Fast-Flux & Suspicious)
    sampled_abuse = np.random.choice(malicious_from_abuse, min(len(all_benign), len(malicious_from_abuse)), replace=False)
    half = len(sampled_abuse) // 2
    for i, d in enumerate(sampled_abuse):
        if i < half: # Fast-Flux Signature
            data.append([len(d), calculate_entropy(d), calculate_digit_ratio(d), d.count('.'), 
                         np.random.randint(10, 121), np.random.randint(8, 40), round(np.random.uniform(10, 25), 2), 2])
        else: # Suspicious/C2 Signature
            data.append([len(d), calculate_entropy(d), calculate_digit_ratio(d), d.count('.'), 
                         np.random.randint(60, 201), np.random.randint(4, 12), round(np.random.uniform(5, 15), 2), 3])

    # Create and Shuffle
    df = pd.DataFrame(data, columns=["domain_length", "entropy", "digit_ratio", "subdomain_depth", "ttl", "unique_ip_count", "query_rate", "label"])
    df = df.sample(frac=1).reset_index(drop=True)
    
    output_file = 'dns_features.csv'
    df.to_csv(output_file, index=False)
    print(f"Successfully generated {output_file} with {len(df)} rows.")

if __name__ == "__main__":
    generate_dns_dataset()