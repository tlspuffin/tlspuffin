from datetime import datetime
from typing import Callable, Union, List

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import ticker

tick_formatter = ticker.FuncFormatter(lambda x, pos: "%dmin" % (x * 60) if x < 1 else "%dh" % x)

font = {'size': 8}

matplotlib.rc('font', **font)


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
    except TypeError:
        # Indexing None values
        return False


# https://colorbrewer2.org/#type=diverging&scheme=RdYlBu&n=3
RED = '#ca0020'
BLUE = '#0571b0'


def plot_single(ax, times, data: List[dict],
                selector: Callable[[dict], Union[int, float]],
                name: str,
                color: str = RED,
                smooth=False):
    if not is_available(data[0], selector):
        ax.set_ylabel("Data not available")
        return

    ax.xaxis.set_major_formatter(tick_formatter)

    y = [selector(row) for row in data]

    print("Max value in plotted data: " + str(np.max(y)))

    if smooth:
        # ax.plot(times[:len(y)], y, label=name, color=color + "32")
        kernel_size = int(len(y) / 50)
        y = np.convolve(y, np.ones(kernel_size) / kernel_size, mode='valid')

    ax.plot(times[:len(y)], y, label=name, color=color)
    ax.set_ylabel(name, color=color)

    # plt.setp(ax.get_xticklabels(), rotation=30, ha='right')


def plot_with_other(ax, times, data: List[dict],
                    selector_a: Callable[[dict], Union[int, float]],
                    name_a: str,
                    selector_b: Callable[[dict], Union[int, float]] = lambda stats: stats["total_execs"],
                    name_b: str = 'Total Execs',
                    smooth=False,
                    log=False):
    if not is_available(data[0], selector_a) or not is_available(data[0], selector_b):
        ax.set_ylabel("Data not available")
        return

    if log and name_b == 'Total Execs':
        name_b = 'Global Total Execs'
        ax.xaxis.set_major_formatter(tick_formatter)
        y = [selector_b(row) for row in data]
        if int(len(y)) > 50:
            kernel_size = int(len(y) / 50)
            y = np.convolve([int(item) for item in y], np.ones(kernel_size) / kernel_size, mode='valid')
            times_ = times[:len(y)]
        else:
            times_ = times
        ax.plot(times_, y, label=name_b, color=BLUE)
        ax.set_ylabel(name_b, color=BLUE)
    else:
        ax.xaxis.set_major_formatter(tick_formatter)
        ax.plot(times, [selector_b(row) for row in data], label=name_b, color=BLUE)
        ax.set_ylabel(name_b, color=BLUE)

    other_ax = ax.twinx()

    y = [selector_a(row) for row in data]

    if smooth and int(len(y)) > 50:
        # other_ax.plot(times[:len(y)], y, label=name_a, color="#ca002032")
        kernel_size = int(len(y) / 50)
        y = np.convolve([int(item) for item in y], np.ones(kernel_size) / kernel_size, mode='valid')

    other_ax.plot(times[:len(y)], y, label=name_a, color=RED)
    other_ax.set_ylabel(name_a, color=RED)

    # plt.setp(ax.get_xticklabels(), rotation=30, ha='right')


def spread_xy(start_date, client_data, trunc_minutes=None):
    times = []
    data = []

    for client_datum in client_data:
        time = datetime.fromtimestamp(client_datum["time"]["secs_since_epoch"])
        times.append(time - start_date)
        data.append(client_datum)

    times = [t.total_seconds() / 60 / 60 for t in times]  # in hours

    if trunc_minutes:
        i = np.argwhere(np.array(times) >= trunc_minutes / 60)[0][0]
        print(i)
        times = times[:i]
        data = data[:i]

    return times, data


def plot_stats(start_date, client_stats: List[dict], global_stats: List[dict], fewer=False):
    times, data = spread_xy(start_date, client_stats)
    times_global, data_global = spread_xy(start_date, global_stats)

    if not fewer:
        fig, ((ax1, ax2), (ax3, ax4), (ax5, ax6), (ax7, ax8), (ax9, ax10), (ax11, ax12), (ax13, ax14),
              (ax15, ax16), (ax17, ax18)) = plt.subplots(9, 2, sharex="all", figsize=(10, 15))

        # Corpi
        plot_with_other(ax1, times, data, lambda stats: stats["objective_size"], "Obj")
        plot_with_other(ax2, times, data, lambda stats: stats["corpus_size"], "Corpus")
        # Errors
        plot_with_other(ax3, times, data, lambda stats: stats["errors"]["ssl_error"], "SSL E")
        # Corpus vs Errors
        plot_with_other(ax4, times, data, lambda stats: stats["objective_size"], "Obj",
                        lambda stats: stats["errors"]["ssl_error"], "SSL E")
        # Coverage
        plot_with_other(ax5, times, data, lambda stats: stats["coverage"]["discovered"], "Coverage")

        # Performance
        plot_with_other(ax6, times, data, lambda stats: stats["exec_per_sec"], "Execs/s", smooth=True)

        # Traces and Terms
        plot_with_other(ax7, times, data, lambda stats: stats["trace"]["max_trace_length"], "Max Trace Len")
        plot_with_other(ax8, times, data, lambda stats: stats["trace"]["max_term_size"], "Max Term Size")

        plot_with_other(ax9, times, data, lambda stats: stats["trace"]["mean_trace_length"], "Mean Trace Len",
                        smooth=True)
        plot_with_other(ax10, times, data, lambda stats: stats["trace"]["mean_term_size"], "Mean Term Size",
                        smooth=True)

        plot_with_other(ax11, times, data, lambda stats: stats["trace"]["min_trace_length"], "Min Trace Len")
        plot_with_other(ax12, times, data, lambda stats: stats["trace"]["min_term_size"], "Min Term Size")

        plot_with_other(ax13, times, data, lambda stats: stats["intro"]["scheduler"], "Sched Perf")
        plot_with_other(ax14, times, data, lambda stats: stats["intro"]["elapsed_cycles"], "Cycles")

        plot_with_other(ax15, times, data, lambda stats: stats["intro"]["introspect_features"]["mutate"],
                        "Mut Perf")
        plot_with_other(ax16, times, data, lambda stats: stats["intro"]["introspect_features"]["target_execution"],
                        "PUT Perf")

        # Global Performance
        plot_with_other(ax17, times_global, data_global, lambda log: log["corpus_size"], "Corpus Size", log=True,
                        smooth=True)
        plot_with_other(ax18, times_global, data_global,
                        lambda log: log["exec_per_sec"], "Global Execs/s",
                        lambda log: log["objective_size"], "Global Objective",
                        smooth=True, log=True)

    else:
        fig, (ax1, ax2, ax3, ax4, ax5, ax6) = plt.subplots(6, 1, figsize=(10, 20))

        # Global Performance
        plot_with_other(ax1, times_global, data_global,
                        lambda stats: stats["exec_per_sec"], "G Execs/s",
                        lambda stats: stats["corpus_size"], "G Corpus",
                        smooth=True, log=True)
        plot_with_other(ax2, times_global, data_global,
                        lambda stats: stats["exec_per_sec"], "G Execs/s",
                        lambda stats: stats["objective_size"], "G Obj",
                        smooth=True, log=True)
        # Errors
        # plot_with_other(ax3, times, data, lambda stats: stats["errors"]["ssl_error"], "SSL E")
        # Coverage
        plot_with_other(ax4, times, data,
                        lambda stats: stats["coverage"]["discovered"], "Coverage")
        # Performance
        plot_with_other(ax5, times, data,
                        lambda stats: stats["exec_per_sec"], "Execs/s",
                        smooth=True)
        plot_with_other(ax6, times, data,
                        lambda stats: stats["intro"]["introspect_features"]["target_execution"],
                        "PUT Perf")

    return fig
