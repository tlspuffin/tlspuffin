import sys

import pandas as pd

import re

def parse_time(t: str) -> int:
    """
    Parses a time string format like '10d', '5h', '30m', or '45s'
    and returns the total duration in seconds.
    """
    match = re.fullmatch(r"(\d+)([dhms])", t.strip().lower())

    if not match:
        raise ValueError(#format
            f"Invalid time format: '{t}'. Expected format like '10d', '5h', '30m', or '45s'."
        )

    value, unit = match.groups()
    value = int(value)

    factors = {
        's': 1,
        'm': 60,
        'h': 3600,
        'd': 86400
    }

    return value * factors[unit]

def analyze_perfs(file_path: str):
    # 1. Load data
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")

    duration = parse_time(df["Timeout"][0])

    df["Executions per core"] = df["Executions"] / df["Core count"]
    # calculate the mean of "Executions per core" for each "Run" and standard deviation
    data = df.groupby(["Run"])["Executions per core"].agg(["mean", "std"])
    data["Executions"] = df.groupby("Run")["Executions"].mean()
    # mean_per_run = df.groupby(["Run"])["Executions per core"].mean()
    # std_per_run = df.groupby(["Run"])["Executions per core"].std()

    data["mean_per_run_per_second"] = data["mean"] / duration
    data["std_per_run_per_second"] = data["std"] / duration

    # pretty print the data as a table
    print(data[["Executions","mean_per_run_per_second", "std_per_run_per_second"]])


if __name__ == "__main__":
    csv_file = "results_perfs.csv"

    if len(sys.argv) > 1:
        csv_file = sys.argv[1]

    analyze_perfs(csv_file)
