import sys

import pandas as pd


def analyze_ablation_study_per_buckets(file_path: str):
    # 1. Load data
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")

    "Bucket,Experiment,Found,Lost"

    data =  df[df["Found"] > 0]
    data = data.groupby(["Experiment"])["Bucket"].agg(["count"])
    data["Lost"] = data["count"].max() - data["count"]
    print(data)


if __name__ == "__main__":
    csv_file = "ablation_per_bucket.csv"

    if len(sys.argv) > 1:
        csv_file = sys.argv[1]

    analyze_ablation_study_per_buckets(csv_file)
