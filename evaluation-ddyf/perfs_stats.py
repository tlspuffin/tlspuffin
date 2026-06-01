import sys

import pandas as pd


def analyze_perfs(file_path: str):
    # 1. Load data
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")

    df["Executions per core"] = df["Executions"] / df["Core count"]
    # calculate the mean of "Executions per core" for each "Run" and standard deviation
    data = df.groupby(["Run"])["Executions per core"].agg(["mean", "std"])
    data["Executions"] = df.groupby("Run")["Executions"].mean()
    # mean_per_run = df.groupby(["Run"])["Executions per core"].mean()
    # std_per_run = df.groupby(["Run"])["Executions per core"].std()

    data["mean_per_run_per_second"] = data["mean"] / 3600
    data["std_per_run_per_second"] = data["std"] / 3600

    # pretty print the data as a table
    print(data[["Executions","mean_per_run_per_second", "std_per_run_per_second"]])


if __name__ == "__main__":
    csv_file = "results_perfs.csv"

    if len(sys.argv) > 1:
        csv_file = sys.argv[1]

    analyze_perfs(csv_file)
