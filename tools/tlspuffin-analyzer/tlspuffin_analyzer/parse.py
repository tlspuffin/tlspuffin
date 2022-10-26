from binascii import hexlify
from io import BytesIO
from itertools import groupby
from operator import itemgetter

import dateparser
from jsonslicer import JsonSlicer


def load_json_slurpy(json_path, client_id=None):
    filtered = []

    print("Reading...")
    with open(json_path) as stats:
        try:
            print("Parsing...")
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
