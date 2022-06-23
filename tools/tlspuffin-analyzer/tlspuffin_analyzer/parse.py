from binascii import hexlify
from io import BytesIO
from itertools import groupby
from operator import itemgetter

import dateparser
from jsonslicer import JsonSlicer

GLOBAL_LOG_STR = "[Stats] (GLOBAL)"


def load_json_slurpy(json_path, worker_id):
    filtered = []

    print("Reading...")
    with open(json_path) as stats:
        try:
            print("Parsing...")
            for dic in JsonSlicer(stats, (), yajl_allow_multiple_values=True, yajl_allow_partial_values=True):
                if worker_id is None or dic["id"] == worker_id:
                    filtered.append(dic)
        except Exception as e:
            print("Failed during parsing! Returning partial data!")
            print(e)
            return filtered

    return filtered


def load_json_slurpy_log(json_path):
    filtered = []

    with open(json_path) as log:
        try:
            for dic in JsonSlicer(log, (), yajl_allow_multiple_values=True, yajl_allow_partial_values=True):
                if GLOBAL_LOG_STR in dic["message"]:
                    item = log_parse_item(dic)
                    filtered.append(item)
        except Exception as e:
            print("Failed during log file parsing! Returning partial data!")
            print(e)
            return filtered

    return filtered


def group_by_id(all_stats):
    sortkeyfn = itemgetter("id")
    return map(lambda t: t[1], groupby(sorted(all_stats, key=sortkeyfn), key=sortkeyfn))


def filter_by_id(all_stats, id):
    return [item for item in all_stats if item["id"] == id]


def log_parse_item(dic):
    raw_data = [field.split(" ")[-1] for field in dic["message"].split(",")]
    item = {
        "time": dateparser.parse(dic["time"]),
        "clients": raw_data[0],
        "corpus": raw_data[1],
        "obj": raw_data[2],
        "total_execs": raw_data[3],
        "exec_per_sec": raw_data[4],
    }
    return item
