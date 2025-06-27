import dateparser
import os
import subprocess
from IPython.display import display, Markdown
from binascii import hexlify
from datetime import datetime
from io import BytesIO
from itertools import groupby
from jsonslicer import JsonSlicer
from operator import itemgetter


def get_start_date(stats):
    return datetime.fromtimestamp(stats[0]['time']['secs_since_epoch'])


def get_end_date(stats):
    return datetime.fromtimestamp(stats[-1]['time']['secs_since_epoch'])


def get_length(stats):
    return datetime.fromtimestamp(len(stats))


def get_keys(all_stats):
    return flatten(all_stats[0]).keys()


def load_json_slurpy(json_path, client_id=None):
    filtered = []

    print("Reading... ", end=" ")
    with open(json_path) as stats:
        try:
            print("Parsing... ", end=" ")
            for dic in JsonSlicer(stats, (), yajl_allow_multiple_values=True, yajl_allow_partial_values=True):
                if dic["type"] == "global" or client_id is None or dic["id"] == client_id:
                    filtered.append(dic)
        except Exception as e:
            print("Failed during parsing! Returning partial data!")
            print(e)
            return filtered

    return filtered


def group_by_id(all_stats):
    sortkeyfn = itemgetter("id")
    return map(lambda t: t[1], groupby(sorted(all_stats, key=sortkeyfn), key=sortkeyfn))


def display_readme(path, num=0):
    with open(path, "r") as file:
        display(Markdown(file.read()))


def extract_logs(puffin_path, experiment, num=0):
    experiments_path = puffin_path + "experiments"
    stats_path = "%s/%s/log/stats.json" % (experiments_path, experiment)
    print("Loading file \"%s\". -> " % stats_path, end=" ")

    # If file at stats_path, first call the script `./tools/reduceStats.sh` on "experiment" and print out the stdout
    if os.path.isfile(stats_path):
        size_bytes = os.path.getsize(stats_path)
        if size_bytes > 100 * 1024 * 1024:  # 100MB
            try:
                result = subprocess.run(
                    ["./tools/reduceStats.sh", experiment],
                    cwd=puffin_path,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                print("Stats reducing script output: ", result.stdout.replace('\n', ' '), end=" -> ")
                stats_path = "%s/%s/log/stats-sampled.json" % (experiments_path, experiment)
                print("Now loading file \"%s\". -> " % stats_path, end=" ")
            except subprocess.CalledProcessError as e:
                print("Script failed with error:")
                print(e.stderr.replace('\n', ' '))
                exit(1)
        else:
            print(f"Stats file is under 100MB ({size_bytes / (1024 * 1024):.2f}MB)...  ", end="")
    else:
        print(f"Stats file not found: {stats_path}")

    stats = load_json_slurpy(stats_path, 1)

    if not stats:
        print("Stats are empty.")
        exit(0)

    # keys_stats = get_keys(stats)
    # print("Available keys (stats): %s" % keys_stats)

    start_date = get_start_date(stats)
    end_date = get_end_date(stats)
    client_stats = [stat for stat in stats if stat["type"] == "client"]
    global_stats = [stat for stat in stats if stat["type"] == "global"]

    display_readme("%s/%s/README.md" % (experiments_path, experiment), num)
    if num != 0:
        print("Campaign information #" + str(num))
        print("    - length: " + str(end_date - start_date))
        print("    - number global entries: " + "{:,}".format(len(global_stats)))
        print("    - number client entries: " + "{:,}".format(len(client_stats)))
    if num == 1:
        print("    => Graphs will be in red and orange\n")
    if num == 2:
        print("    => Graphs will be in blue and cyan\n")

    return (start_date, client_stats, global_stats)
