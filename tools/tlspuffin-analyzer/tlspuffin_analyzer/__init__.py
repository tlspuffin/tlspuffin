from binascii import hexlify
from datetime import datetime
from io import BytesIO
from itertools import groupby
from operator import itemgetter
from typing import Callable, Union

import matplotlib.pyplot as plt
import numpy as np
import paramiko as paramiko
from jsonslicer import JsonSlicer
from tlspuffin_analyzer.stats_type import ClientStatistics


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


def is_available(stat: ClientStatistics, selector: Callable[[ClientStatistics], Union[int, float]]):
    try:
        selector(stat)
        return True
    except AttributeError:
        return False


def plot_with_other(ax, times, data: list[ClientStatistics],
                    selector_a: Callable[[ClientStatistics], Union[int, float]],
                    name_a: str,
                    selector_b: Callable[[ClientStatistics], Union[int, float]] = lambda stats: stats.total_execs,
                    name_b: str = 'Total Execs',
                    smooth=False):
    if not is_available(data[0], selector_a) or not is_available(data[0], selector_b):
        ax.set_ylabel("Data not available")
        return

    ax.plot(times, [selector_b(row) for row in data], label=name_b)
    ax.set_ylabel(name_b)

    inner_ax = ax.twinx()
    y = [selector_a(row) for row in data]

    if smooth:
        kernel_size = int(len(y) / 50)
        y = np.convolve(y, np.ones(kernel_size) / kernel_size, mode='valid')

    inner_ax.plot(times[:len(y)], y, label=name_a, color='red')
    inner_ax.set_ylabel(name_a)

    plt.setp(ax.get_xticklabels(), rotation=30, ha='right')


def plot_client_stats(start_date, client_stats: list[dict]):
    times = []
    data = []

    for client_stat in client_stats:
        mapped = ClientStatistics.from_dict(client_stat)
        time = datetime.fromtimestamp(mapped.time.secs_since_epoch)
        times.append(time - start_date)
        data.append(mapped)

    times = [t.total_seconds() / 60 for t in times]

    fig, ((ax1, ax2), (ax3, ax4), (ax5, ax6), (ax7, ax8), (ax9, ax10), (ax11, ax12), (ax13, ax14),
          (ax15, ax16)) = plt.subplots(8, 2, sharex="all")

    # Corpi
    plot_with_other(ax1, times, data, lambda stats: stats.objective_size, "Objectives")
    plot_with_other(ax2, times, data, lambda stats: stats.corpus_size, "Corpus Size")
    # Errors
    plot_with_other(ax3, times, data, lambda stats: stats.errors.ssl_error, "SSL Errors")
    # Corpus vs Errors
    plot_with_other(ax4, times, data, lambda stats: stats.objective_size, "Objectives",
                    lambda stats: stats.errors.ssl_error, "SSL Errors")
    # Coverage
    plot_with_other(ax5, times, data, lambda stats: stats.coverage.discovered, "Coverage")
    # Performance
    plot_with_other(ax6, times, data, lambda stats: stats.exec_per_sec, "Execs/s", smooth=True)
    # Traces and Terms
    plot_with_other(ax7, times, data, lambda stats: stats.trace.max_trace_length, "Max Trace Length")
    plot_with_other(ax8, times, data, lambda stats: stats.trace.max_term_size, "Max Term Size")

    plot_with_other(ax9, times, data, lambda stats: stats.trace.mean_trace_length, "Mean Trace Length", smooth=True)
    plot_with_other(ax10, times, data, lambda stats: stats.trace.mean_term_size, "Mean Term Size", smooth=True)

    plot_with_other(ax11, times, data, lambda stats: stats.trace.min_trace_length, "Min Trace Length")
    plot_with_other(ax12, times, data, lambda stats: stats.trace.min_term_size, "Min Tern Size")

    plot_with_other(ax13, times, data, lambda stats: stats.intro.scheduler, "Scheduler Perf Share")
    plot_with_other(ax14, times, data, lambda stats: stats.intro.elapsed_cycles, "Elapsed Cycles")

    plot_with_other(ax15, times, data, lambda stats: stats.intro.introspect_features.mutate, "Mutation Perf Share")
    plot_with_other(ax16, times, data, lambda stats: stats.intro.introspect_features.target_execution, "PUT Perf Share")

    return fig
