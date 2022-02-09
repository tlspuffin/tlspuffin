from binascii import hexlify
from io import BytesIO
from itertools import groupby
from operator import itemgetter
from typing import List

import paramiko as paramiko
import dateparser
from jsonslicer import JsonSlicer

from tlspuffin_analyzer.stats_type import ClientStatistics

GLOBAL_LOG_STR = "[Stats] (GLOBAL)"

def agent_auth(transport, username):
    """
    Attempt to authenticate to the given transport using any of the private
    keys available from an SSH agent.
    """

    agent = paramiko.Agent()
    agent_keys = agent.get_keys()
    if len(agent_keys) == 0:
        return

    for key in agent_keys:
        print("Trying ssh-agent key %s" % hexlify(key.get_fingerprint()))
        try:
            transport.auth_publickey(username, key)
            print("... success!")
            return
        except paramiko.SSHException:
            print("... nope.")


def load_json_slurpy_ssh(host, base_path, experiment, user, worker_id=None):
    t = paramiko.Transport((host, 22))
    t.use_compression(True)
    t.start_client()
    agent_auth(t, user)

    sftp = paramiko.SFTPClient.from_transport(t)

    print("Pre-fetching %s/experiments/%s/stats.json ..." % (base_path, experiment))
    file_stats = sftp.open("%s/experiments/%s/stats.json" % (base_path, experiment), "r")
    file_stats.prefetch()
    print("Reading... (if taking too much time, do not use --ssh)")
    data_stats = file_stats.read()
    print("Parsing...")
    stats = list(
        filter_by_id(JsonSlicer(BytesIO(data_stats), (), yajl_allow_multiple_values=True, yajl_allow_partial_values=True),
                     worker_id))
    print("Pre-fetching %s/experiments/%s/tlspuffin-log.json ..." % (base_path, experiment))
    file_log = sftp.open("%s/experiments/%s/tlspuffin-log.json" % (base_path, experiment), "r")
    file_log.prefetch()
    print("Reading... (if taking too much time, do not use --ssh)")
    data_log = file_log.read()
    log = []
    print("Parsing...")
    for dic in JsonSlicer(BytesIO(data_log), (), yajl_allow_multiple_values=True, yajl_allow_partial_values=True):
        if GLOBAL_LOG_STR in dic["message"]:
            item = log_parse_item(dic)
            log.append(item)

    return(stats, log)


#def dict_to_client_stats(dict: dict) -> ClientStatistics:
#    ClientStatistics()


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
    item = {}
    raw_data = [field.split(" ")[-1] for field in dic["message"].split(",")]
    item = {"time": dateparser.parse(dic["time"]),
            "clients" : raw_data[0],
            "corpus":  raw_data[1],
            "obj":  raw_data[2],
            "total_execs":  raw_data[3],
            "exec_per_sec":  raw_data[4],
    }
    return(item)
