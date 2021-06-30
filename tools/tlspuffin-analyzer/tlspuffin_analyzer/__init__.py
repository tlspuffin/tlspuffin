from binascii import hexlify
from datetime import datetime
from io import StringIO, BytesIO
from itertools import groupby
from operator import itemgetter

import matplotlib.pyplot as plt
import numpy as np
import paramiko as paramiko
from jsonslicer import JsonSlicer


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


def load_json_slurpy_ssh(host, base_path, experiment, user="mammann"):
    t = paramiko.Transport((host, 22))
    t.use_compression(True)
    t.start_client()
    agent_auth(t, user)

    sftp = paramiko.SFTPClient.from_transport(t)

    file = sftp.open("%s/experiments/%s/stats.json" % (base_path, experiment), "r")
    file.prefetch()
    data = file.read()

    return list(JsonSlicer(BytesIO(data), (), yajl_allow_multiple_values=True, yajl_allow_partial_values=True))


def load_json_slurpy(json_path):
    with open(json_path) as stats:
        return list(JsonSlicer(stats, (), yajl_allow_multiple_values=True, yajl_allow_partial_values=True))


def get_start_date(all_stats):
    return datetime.fromtimestamp(all_stats[0]['time']['secs_since_epoch'])


def get_keys(all_stats):
    return flatten(all_stats[0]).keys()


def flatten(d):
    out = {}
    for key, val in d.items():
        if isinstance(val, dict):
            deeper = flatten(val).items()
            out.update({key + '_' + key2: val2 for key2, val2 in deeper})
        else:
            out[key] = val
    return out


def group_by_id(all_stats):
    sortkeyfn = itemgetter("id")
    return map(lambda t: t[1], groupby(sorted(all_stats, key=sortkeyfn), key=sortkeyfn))


def plot_with_other(ax, times, data, key, key_other='total_execs', smooth=False):
    if key not in data[0] or key_other not in data[0]:
        ax.set_ylabel("Data not available")
        return

    ax.plot(times, [row[key_other] for row in data], label=key_other)
    ax.set_ylabel(key_other)

    inner_ax = ax.twinx()
    y = [row[key] for row in data]

    if smooth:
        kernel_size = int(len(y) / 50)
        y = np.convolve(y, np.ones(kernel_size) / kernel_size, mode='valid')

    inner_ax.plot(times[:len(y)], y, label=key, color='red')
    inner_ax.set_ylabel(key)

    plt.setp(ax.get_xticklabels(), rotation=30, ha='right')


def plot_client_stats(start_date, client_stats):
    times = []
    data = []

    for client_stats in client_stats:
        time = datetime.fromtimestamp(client_stats['time']['secs_since_epoch'])
        times.append(time - start_date)

        # Sats data
        flat_stats = flatten(client_stats)
        data.append(flat_stats)

    times = [t.total_seconds() / 60 for t in times]

    fig, ((ax1, ax2), (ax3, ax4), (ax5, ax6), (ax7, ax8), (ax9, ax10), (ax11, ax12)) = plt.subplots(6, 2, sharex="all")

    # Corpi
    plot_with_other(ax1, times, data, "objective_size")
    plot_with_other(ax2, times, data, "corpus_size")
    # Errors
    plot_with_other(ax3, times, data, "errors_ssl_error")
    # Corpus vs Errors
    plot_with_other(ax4, times, data, "objective_size", key_other="errors_ssl_error")
    # Coverage
    plot_with_other(ax5, times, data, "coverage_discovered")
    # Performance
    plot_with_other(ax6, times, data, "exec_per_sec", smooth=True)
    # Traces and Terms
    plot_with_other(ax7, times, data, "trace_max_trace_length")
    plot_with_other(ax8, times, data, "trace_max_term_size")

    plot_with_other(ax9, times, data, "trace_mean_trace_length", smooth=True)
    plot_with_other(ax10, times, data, "trace_mean_term_size", smooth=True)

    plot_with_other(ax11, times, data, "trace_min_trace_length")
    plot_with_other(ax12, times, data, "trace_min_term_size")

    return fig

