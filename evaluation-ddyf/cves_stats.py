import pandas as pd


def analyze_vulnerability_campaigns(file_path):
    # 1. Load data
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return

    # 2. Parse the Occurrence Date (the time the trace was recorded)
    # Format matches: 2026-01-07_01-13-50
    df["OccurrenceDate"] = pd.to_datetime(
        df["Date"], format="%Y-%m-%d_%H-%M-%S"
    )

    # 3. Extract Campaign Start Time from the "Campaign name"
    # Format: 2026-01-07--openssl...--00-48-31--0
    # We take the first part as date and the second-to-last part as time
    def extract_start_time(name):
        try:
            parts = name.split("--")
            date_part = parts[0]  # '2026-01-07'
            time_part = parts[-2]  # '00-48-31'
            return pd.to_datetime(
                f"{date_part}_{time_part}", format="%Y-%m-%d_%H-%M-%S"
            )
        except (IndexError, ValueError):
            return pd.NaT

    df["CampaignStartTime"] = df["Campaign name"].apply(extract_start_time)

    # 4. Calculate Elapsed Seconds from campaign start to detection
    df["ElapsedSeconds"] = (
        df["OccurrenceDate"] - df["CampaignStartTime"]
    ).dt.total_seconds()

    # 5. Get the FIRST occurrence for each CVE in each Campaign
    # This is the "min of individual campaigns"
    first_hits = (
        df.groupby(["CVE", "Campaign name"])["ElapsedSeconds"].min().reset_index()
    )

    # 6. Calculate Global Statistics per CVE
    total_campaigns_count = df["Campaign name"].nunique()

    # Aggregate the first_hits data
    cve_stats = (
        first_hits.groupby("CVE")
        .agg(
            campaigns_present=("Campaign name", "count"),
            min_time=("ElapsedSeconds", "min"),
            mean_time=("ElapsedSeconds", "mean"),
            std_dev=("ElapsedSeconds", "std"),
            max_time=("ElapsedSeconds", "max"),  # Added max for sanity checking
        )
        .reset_index()
    )

    # Calculate proportion of total campaigns
    cve_stats["proportion"] = cve_stats["campaigns_present"] / total_campaigns_count

    # --- OUTPUT RESULTS ---

    print(f"Total Unique Campaigns Processed: {total_campaigns_count}\n")

    print("=== Summary Statistics per CVE ===")
    print("Calculated from the first apparition in each campaign.")

    # Formatting for display
    header = f"{'CVE':<15} | {'Prop':<8} | {'Min':<10} | {'Mean':<10} | {'Std':<10}"
    print(header)
    print("-" * len(header))

    # Rows
    for _, row in cve_stats.iterrows():
        print(
            f"{row['CVE']:<15} | {row['proportion']:<8.0%} | {row['min_time']:<10.1f} | {row['mean_time']:<10.1f} | {row['std_dev']:<10.1f}"
        )

    print()

    def format_duration(seconds):
        prefix = ""
        if seconds < 0:
            prefix = "-"
            seconds = abs(seconds)
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        s = int(seconds % 60)
        return f"{prefix}{h:02d}h {m:02d}m {s:02d}s"

    # Sort for readability
    first_hits = first_hits.sort_values(by=["CVE", "ElapsedSeconds"])
    for _, row in first_hits.iterrows():
        print(
            f"CVE: {row['CVE']:<15} | Time: {format_duration(row['ElapsedSeconds']):>10} | Campaign: {row['Campaign name']}"
        )


if __name__ == "__main__":
    # Ensure your CSV file is in the same directory or provide the full path
    analyze_vulnerability_campaigns("cve_list.csv")
    pass
