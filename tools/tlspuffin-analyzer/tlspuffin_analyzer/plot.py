from datetime import datetime
from typing import Callable, Union, List

import matplotlib.pyplot as plt
import numpy as np
from matplotlib import ticker

from tlspuffin_analyzer.stats_type import ClientStatistics


def get_start_date(stats):
    return datetime.fromtimestamp(stats[0]['time']['secs_since_epoch'])


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


def is_available(stat: dict, selector: Callable[[dict], Union[int, float]]):
    try:
        selector(stat)
        return True
    except KeyError:
        return False


# https://colorbrewer2.org/#type=diverging&scheme=RdYlBu&n=3
RED = '#ca0020'
BLUE = '#0571b0'


def plot_single(ax, times, data: List[dict],
                selector: Callable[[dict], Union[int, float]],
                name: str,
                smooth=False):
    if not is_available(data[0], selector):
        ax.set_ylabel("Data not available")
        return

    ax.xaxis.set_major_formatter(ticker.FormatStrFormatter("%dh"))

    y = [selector(row) for row in data]

    if smooth:
        kernel_size = int(len(y) / 50)
        y = np.convolve(y, np.ones(kernel_size) / kernel_size, mode='valid')

    ax.plot(times[:len(y)], y, label=name, color=RED)
    ax.set_ylabel(name, color=RED)

    plt.setp(ax.get_xticklabels(), rotation=30, ha='right')


def plot_with_other(ax, times, data: List[dict],
                    selector_a: Callable[[dict], Union[int, float]],
                    name_a: str,
                    selector_b: Callable[[dict], Union[int, float]] = lambda stats: stats["total_execs"],
                    name_b: str = 'Total Execs',
                    smooth=False):
    if not is_available(data[0], selector_a) or not is_available(data[0], selector_b):
        ax.set_ylabel("Data not available")
        return

    ax.xaxis.set_major_formatter(ticker.FormatStrFormatter("%dh"))

    ax.plot(times, [selector_b(row) for row in data], label=name_b, color=BLUE)
    ax.set_ylabel(name_b, color=BLUE)

    inner_ax = ax.twinx()
    y = [selector_a(row) for row in data]

    if smooth:
        kernel_size = int(len(y) / 50)
        y = np.convolve(y, np.ones(kernel_size) / kernel_size, mode='valid')

    inner_ax.plot(times[:len(y)], y, label=name_a, color=RED)
    inner_ax.set_ylabel(name_a, color=RED)

    plt.setp(ax.get_xticklabels(), rotation=30, ha='right')


def spread_xy(start_date, client_stats):
    times = []
    data = []

    for client_stat in client_stats:
        time = datetime.fromtimestamp(client_stat["time"]["secs_since_epoch"])
        times.append(time - start_date)
        data.append(client_stat)

    times = [t.total_seconds() / 60 / 60 for t in times]  # in hours

    return times, data


def plot_client_stats(start_date, client_stats: List[dict]):
    times, data = spread_xy(start_date, client_stats)

    fig, ((ax1, ax2), (ax3, ax4), (ax5, ax6), (ax7, ax8), (ax9, ax10), (ax11, ax12), (ax13, ax14),
          (ax15, ax16)) = plt.subplots(8, 2, sharex="all")

    # Corpi
    plot_with_other(ax1, times, data, lambda stats: stats["objective_size"], "Objectives")
    plot_with_other(ax2, times, data, lambda stats: stats["corpus_size"], "Corpus Size")
    # Errors
    plot_with_other(ax3, times, data, lambda stats: stats["errors"]["ssl_error"], "SSL Errors")
    # Corpus vs Errors
    plot_with_other(ax4, times, data, lambda stats: stats["objective_size"], "Objectives",
                    lambda stats: stats["errors"]["ssl_error"], "SSL Errors")
    # Coverage
    plot_with_other(ax5, times, data, lambda stats: stats["coverage"]["discovered"], "Coverage")
    # Performance
    plot_with_other(ax6, times, data, lambda stats: stats["exec_per_sec"], "Execs/s", smooth=True)
    # Traces and Terms
    plot_with_other(ax7, times, data, lambda stats: stats["trace"]["max_trace_length"], "Max Trace Length")
    plot_with_other(ax8, times, data, lambda stats: stats["trace"]["max_term_size"], "Max Term Size")

    plot_with_other(ax9, times, data, lambda stats: stats["trace"]["mean_trace_length"], "Mean Trace Length", smooth=False)
    plot_with_other(ax10, times, data, lambda stats: stats["trace"]["mean_term_size"], "Mean Term Size", smooth=False)

    plot_with_other(ax11, times, data, lambda stats: stats["trace"]["min_trace_length"], "Min Trace Length")
    plot_with_other(ax12, times, data, lambda stats: stats["trace"]["min_term_size"], "Min Tern Size")

    plot_with_other(ax13, times, data, lambda stats: stats["intro"]["scheduler"], "Scheduler Perf Share")
    plot_with_other(ax14, times, data, lambda stats: stats["intro"]["elapsed_cycles"], "Elapsed Cycles")

    plot_with_other(ax15, times, data, lambda stats: stats["intro"]["introspect_features"]["mutate"], "Mutation Perf Share")
    plot_with_other(ax16, times, data, lambda stats: stats["intro"]["introspect_features"]["target_execution"], "PUT Perf Share")

    return fig
