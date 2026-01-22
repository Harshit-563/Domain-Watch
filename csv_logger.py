import csv
import os

CSV_FILE = "dns_features.csv"

HEADERS = [
    "domain_length",
    "entropy",
    "digit_ratio",
    "subdomain_depth",
    "ttl",
    "unique_ip_count",
    "query_rate",
    "label"
]

def init_csv():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(HEADERS)

def log_to_csv(features, label):
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(features + [label])
