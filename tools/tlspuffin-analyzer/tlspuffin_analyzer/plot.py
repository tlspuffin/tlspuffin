import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import ticker
from typing import Callable, Union, List

from tlspuffin_analyzer.parse import *

SKIP_START_LENGTH = 500
tick_formatter = ticker.FuncFormatter(lambda x, pos: "%dmin" % (x * 60) if x < 1 else "%dh" % x)

font = {'size': 8}

matplotlib.rc('font', **font)


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
RED = '#d73027'  # dark red
RED2 = '#fc8d59'  # orange
BLUE = '#4575b4'  # dark blue
BLUE2 = '#91bfdb'  # light blue

# RED = '#d73027'  # dark red
# BLUE = '#fc8d59'  # orange
# RED2 = '#4575b4'  # dark blue
# BLUE2 = '#91bfdb'  # light blue


YLABEL_C_1 = RED
YLABEL_C_2 = BLUE

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
        ax.set_ylabel(name_b, color=YLABEL_C_1)
    else:
        ax.xaxis.set_major_formatter(tick_formatter)
        ax.plot(times, [selector_b(row) for row in data], label=name_b, color=BLUE)
        ax.set_ylabel(name_b, color=YLABEL_C_1)

    other_ax = ax.twinx()

    y = [selector_a(row) for row in data]

    if smooth and int(len(y)) > 50:
        # other_ax.plot(times[:len(y)], y, label=name_a, color="#ca002032")
        kernel_size = int(len(y) / 50)
        y = np.convolve([int(item) for item in y], np.ones(kernel_size) / kernel_size, mode='valid')

    other_ax.plot(times[:len(y)], y, label=name_a, color=RED)
    other_ax.set_ylabel(name_a, color=YLABEL_C_2)

    # plt.setp(ax.get_xticklabels(), rotation=30, ha='right')


def plot_with_other_compare(ax, times1, data1: List[dict], times2, data2: List[dict],
                            selector_a: Callable[[dict], Union[int, float]],
                            name_a: str,
                            selector_b: Callable[[dict], Union[int, float]] = lambda stats: stats["total_execs"],
                            name_b: str = 'Total Execs',
                            smooth=False,
                            log=False,
                            divide=None,
                            skip_start=False,
                            no_total=False,
                            twin=None):
    skip_length = SKIP_START_LENGTH
    if not is_available(data1[0], selector_a) or not is_available(data1[0], selector_b) or not is_available(data2[0],
                                                                                                            selector_a) or not is_available(
            data2[0], selector_b):
        ax.set_ylabel("Data not available")
        return

    ax.xaxis.set_major_formatter(tick_formatter)

    if log and name_b == 'Total Execs':
        name_b = 'Global Total Execs'
        y1 = [selector_b(row) for row in data1]
        y2 = [selector_b(row) for row in data2]

        if int(len(y1)) > 50:
            kernel_size1 = int(len(y1) / 50)
            kernel_size2 = int(len(y2) / 50)
            y1 = np.convolve([int(item) for item in y1], np.ones(kernel_size1) / kernel_size1, mode='valid')
            y2 = np.convolve([int(item) for item in y2], np.ones(kernel_size2) / kernel_size2, mode='valid')
            times1_ = times1[:len(y1)]
            times2_ = times2[:len(y2)]
        else:
            times1_ = times1
            times2_ = times2

        if skip_start:
            y1 = y1[skip_length:]
            y2 = y2[skip_length:]
            times1_ = times1_[skip_length:]
            times2_ = times2_[skip_length:]
            name_b = name_b + "(Trunc.)"

        ax.plot(times1_, y1, label=name_b, color=RED2)
        ax.plot(times2_, y2, label=name_b, color=BLUE2)
        ax.set_ylabel(name_b, color=YLABEL_C_1)
    else:
        if not (no_total):
            y1 = [selector_b(row) for row in data1]
            y2 = [selector_b(row) for row in data2]
            ax.plot(times1, y1, label=name_b, color=RED2)
            ax.plot(times2, y2, label=name_b, color=BLUE2)
            ax.set_ylabel(name_b, color=YLABEL_C_1)

    if twin is None:
        other_ax = ax.twinx()
    else:
        other_ax = twin

    y1 = [selector_a(row) for row in data1]
    y2 = [selector_a(row) for row in data2]

    if divide != None:
        y1d = [divide(row) for row in data1]
        y2d = [divide(row) for row in data2]
        y1 = [((100 * y) / d if d != 0 else 0) for (y, d) in zip(y1, y1d)]
        y2 = [((100 * y) / d if d != 0 else 0) for (y, d) in zip(y2, y2d)]
        # Always include 0 in the y axis formatter in divide mode


    if smooth and int(len(y1)) > 50:
        # other_ax.plot(times[:len(y)], y, label=name_a, color="#ca002032")
        kernel_size1 = int(len(y1) / 50)
        kernel_size2 = int(len(y2) / 50)
        y1 = np.convolve([int(item) for item in y1], np.ones(kernel_size1) / kernel_size1, mode='valid')
        y2 = np.convolve([int(item) for item in y2], np.ones(kernel_size2) / kernel_size2, mode='valid')

    x1 = times1[:len(y1)]
    x2 = times2[:len(y2)]

    if skip_start:
        y1 = y1[skip_length:]
        y2 = y2[skip_length:]
        x1 = x1[skip_length:]
        x2 = x2[skip_length:]
        name_a = name_a + "(Tru.)"

    if divide:
        name_a=name_a + "%"

    other_ax.plot(x1, y1, label=name_a, color=RED)
    other_ax.plot(x2, y2, label=name_a, color=BLUE)
    other_ax.set_ylabel(name_a, color=YLABEL_C_2)

    if divide:
        ax.set_ylim(bottom=0)
        other_ax.set_ylim(bottom=0)

    # plt.setp(ax.get_xticklabels(), rotation=30, ha='right')
    return other_ax

def plot_with_other_compare(ax, times1, data1: List[dict], times2, data2: List[dict],
                            selector_a: Callable[[dict], Union[int, float]],
                            name_a: str,
                            selector_b: Callable[[dict], Union[int, float]] = lambda stats: stats["total_execs"],
                            name_b: str = 'Total Execs',
                            smooth=False,
                            log=False,
                            divide=None,
                            skip_start=False,
                            no_total=False):
    skip_length = 500
    if not is_available(data1[0], selector_a) or not is_available(data1[0], selector_b) or not is_available(data2[0],
                                                                                                            selector_a) or not is_available(
            data2[0], selector_b):
        ax.set_ylabel("Data not available")
        return

    ax.xaxis.set_major_formatter(tick_formatter)

    if log and name_b == 'Total Execs':
        name_b = 'Global Total Execs'
        y1 = [selector_b(row) for row in data1]
        y2 = [selector_b(row) for row in data2]

        if int(len(y1)) > 50:
            kernel_size1 = int(len(y1) / 50)
            kernel_size2 = int(len(y2) / 50)
            y1 = np.convolve([int(item) for item in y1], np.ones(kernel_size1) / kernel_size1, mode='valid')
            y2 = np.convolve([int(item) for item in y2], np.ones(kernel_size2) / kernel_size2, mode='valid')
            times1_ = times1[:len(y1)]
            times2_ = times2[:len(y2)]
        else:
            times1_ = times1
            times2_ = times2

        if skip_start:
            y1 = y1[skip_length:]
            y2 = y2[skip_length:]
            times1_ = times1_[skip_length:]
            times2_ = times2_[skip_length:]
            name_b = name_b + "(Trunc.)"

        ax.plot(times1_, y1, label=name_b, color=RED2)
        ax.plot(times2_, y2, label=name_b, color=BLUE2)
        ax.set_ylabel(name_b, color=YLABEL_C_1)
    else:
        if not (no_total):
            y1 = [selector_b(row) for row in data1]
            y2 = [selector_b(row) for row in data2]
            ax.plot(times1, y1, label=name_b, color=RED2)
            ax.plot(times2, y2, label=name_b, color=BLUE2)
            ax.set_ylabel(name_b, color=YLABEL_C_1)

    other_ax = ax.twinx()

    y1 = [selector_a(row) for row in data1]
    y2 = [selector_a(row) for row in data2]

    if divide != None:
        y1d = [divide(row) for row in data1]
        y2d = [divide(row) for row in data2]
        y1 = [((100 * y) / d if d != 0 else 0) for (y, d) in zip(y1, y1d)]
        y2 = [((100 * y) / d if d != 0 else 0) for (y, d) in zip(y2, y2d)]
        # Always include 0 in the y axis formatter in divide mode


    if smooth and int(len(y1)) > 50:
        # other_ax.plot(times[:len(y)], y, label=name_a, color="#ca002032")
        kernel_size1 = int(len(y1) / 50)
        kernel_size2 = int(len(y2) / 50)
        y1 = np.convolve([int(item) for item in y1], np.ones(kernel_size1) / kernel_size1, mode='valid')
        y2 = np.convolve([int(item) for item in y2], np.ones(kernel_size2) / kernel_size2, mode='valid')

    x1 = times1[:len(y1)]
    x2 = times2[:len(y2)]

    if skip_start:
        y1 = y1[skip_length:]
        y2 = y2[skip_length:]
        x1 = x1[skip_length:]
        x2 = x2[skip_length:]
        name_a = name_a + "(Trunc.)"

    other_ax.plot(x1, y1, label=name_a, color=RED)
    other_ax.plot(x2, y2, label=name_a, color=BLUE)
    other_ax.set_ylabel(name_a, color=YLABEL_C_2)

    if divide:
        ax.set_ylim(bottom=0)
        other_ax.set_ylim(bottom=0)

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

def plot_compare_stats(start_date1, client_stats1: List[dict], global_stats1: List[dict], start_date2,
                       client_stats2: List[dict], global_stats2: List[dict], fewer=False, new=False):
    times1, data1 = spread_xy(start_date1, client_stats1)
    times_global1, data_global1 = spread_xy(start_date1, global_stats1)
    times2, data2 = spread_xy(start_date2, client_stats2)
    times_global2, data_global2 = spread_xy(start_date2, global_stats2)

    FS = 15
    VS = 0.0

    if not fewer:
        # Hack to allow text subplots
        f, ((ax1, ax2)) = plt.subplots(1, 2, figsize=(12, 20))
        ax1.set_visible(False)  # Hide the last subplot
        ax2.set_visible(False)  # Hide the last subplot
        f.set_size_inches(20, 1, forward=True)

        # GLOBAL STATS
        plt.figtext(0.1, VS, "Global Stats Analysis", fontsize=FS, ha='left', va='top')
        figGlobal, ((ax1, ax2)) = plt.subplots(1, 2, figsize=(12, 20))

        # Global Performance
        plot_with_other_compare(ax1, times_global1, data_global1, times_global2, data_global2,
                                lambda log: log["corpus_size"], "Global Corpus Size", log=True, smooth=True)
        ax1.set_title("Global Corpus Size Over Time")
        plot_with_other_compare(ax2, times_global1, data_global1, times_global2, data_global2,
                                lambda log: log["exec_per_sec"], "Global Execs/s",
                                lambda log: log["objective_size"], "Global Objective",
                                smooth=True, log=True)
        ax2.set_title("Global Execution Rate vs Objective Size")

        # Corpus and coverage
        plt.figtext(0.1, VS, "Corpus and Coverage Analysis (for 1 client from now on)", fontsize=FS, ha='left',
                    va='top')
        figCorpus, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 20))
        plot_with_other_compare(ax1, times1, data1, times2, data2, lambda stats: stats["corpus_size"], "Corpus")
        ax1.set_title("Corpus Size")
        plot_with_other_compare(ax2, times1, data1, times2, data2, lambda stats: stats["coverage"]["hit"], "Coverage")
        ax2.set_title("Coverage (sancov)")
        # Execs and objective
        plot_with_other_compare(ax3, times1, data1, times2, data2, lambda stats: stats["exec_per_sec"], "Execs/s",
                                smooth=True)
        ax3.set_title("Execution Rate")
        plot_with_other_compare(ax4, times1, data1, times2, data2, lambda stats: stats["objective_size"], "Objective")
        ax4.set_title("Objective Size")

        # SUCCESS STATS
        plt.figtext(0.1, VS, "All Trace Execution Analysis", fontsize=FS, ha='left', va='top')
        figFailure, ((ax1, ax2), (ax3, ax4), (ax5, ax6), (ax7, ax8)) = plt.subplots(4, 2, figsize=(12, 20))
        plot_with_other_compare(ax1, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["all_term_eval_success"], "Term Eval Success",
                                divide=lambda stats: stats["errors"]["all_term_eval"],
                                selector_b=lambda stats: stats["errors"]["all_term_eval"],
                                name_b="All Term Eval",
                                skip_start=True)
        ax1.set_title("Term Evaluation Success Rate")
        twin = plot_with_other_compare(ax2, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["eval_fn_crypto_error"], "Crypto",
                                divide=lambda stats: stats["errors"]["all_term_eval"],
                                selector_b=lambda stats: stats["errors"]["all_term_eval"],
                                name_b="All term Eval",
                                skip_start=False)
        twin = plot_with_other_compare(ax2, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["eval_fn_malformed_error"], "Malf",
                                divide=lambda stats: stats["errors"]["all_term_eval"],
                                skip_start=False,
                                twin=twin, log=False, no_total=True)
        twin = plot_with_other_compare(ax2, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["eval_fn_unknown_error"], "UKWN",
                                divide=lambda stats: stats["errors"]["all_term_eval"],
                                skip_start=False,
                                twin=twin, log=False, no_total=True)
        plot_with_other_compare(ax2, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["eval_fn_codec_error"], "CODEC",
                                divide=lambda stats: stats["errors"]["all_term_eval"],
                                skip_start=False,
                                twin=twin, log=False, no_total=True)
        ax2.set_title("Fn Term Error Rate by type")
        twin = plot_with_other_compare(ax3, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["eval_term_error"], "Term",
                                divide=lambda stats: stats["errors"]["all_term_eval"],
                                skip_start=False,
                                       )
        twin = plot_with_other_compare(ax3, times1, data1, times2, data2,
                                       lambda stats: stats["errors"]["eval_termbug_error"] + stats["errors"][
                                           "eval_codec_error"], "C+TB",
                                divide=lambda stats: stats["errors"]["all_term_eval"],
                                skip_start=False,
                                twin=twin, log=False, no_total=True)
        ax2.set_title("Term Error Rate by type")
        twin = plot_with_other_compare(ax2, times1, data1, times2, data2,
                                       lambda stats: stats["errors"]["eval_fn_crypto_error"], "Crypto",
                                       divide=lambda stats: stats["errors"]["all_term_eval"],
                                       selector_b=lambda stats: stats["errors"]["all_term_eval"],
                                       name_b="All term Eval",
                                       skip_start=False)
        twin = plot_with_other_compare(ax2, times1, data1, times2, data2,
                                       lambda stats: stats["errors"]["eval_fn_malformed_error"], "Malf",
                                       divide=lambda stats: stats["errors"]["all_term_eval"],
                                       skip_start=False,
                                       twin=twin, log=False, no_total=True)
        twin = plot_with_other_compare(ax2, times1, data1, times2, data2,
                                       lambda stats: stats["errors"]["eval_fn_unknown_error"], "UKWN",
                                       divide=lambda stats: stats["errors"]["all_term_eval"],
                                       skip_start=False,
                                       twin=twin, log=False, no_total=True)
        twin = plot_with_other_compare(ax2, times1, data1, times2, data2,
                                       lambda stats: stats["errors"]["eval_term_error"], "Term",
                                       divide=lambda stats: stats["errors"]["all_term_eval"],
                                       skip_start=False,
                                       twin=twin, log=False, no_total=True)
        twin = plot_with_other_compare(ax2, times1, data1, times2, data2,
                                       lambda stats: stats["errors"]["eval_termbug_error"] + stats["errors"][
                                           "eval_codec_error"], "C+TB",
                                       divide=lambda stats: stats["errors"]["all_term_eval"],
                                       skip_start=False,
                                       twin=twin, log=False, no_total=True)
        ax2.set_title("Term Error Rate by type")

        twin = plot_with_other_compare(ax4, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["all_exec_success"], "Trace Exec Success",
                                divide=lambda stats: stats["errors"]["all_exec"],
                                selector_b=lambda stats: stats["errors"]["all_exec"],
                                name_b="All Trace Executions",
                                skip_start=True)
        plot_with_other_compare(ax4, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["all_exec_agent_success"], "+A",
                                divide=lambda stats: stats["errors"]["all_exec"],
                                skip_start=True,
                                twin=twin, log=False, no_total=True)
        ax4.set_title("Trace Execution Success Rate")
        twin = plot_with_other_compare(ax5, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["harness_exec_success"], "Harness Exec Success",
                                divide=lambda stats: stats["errors"]["harness_exec"],
                                selector_b=lambda stats: stats["errors"]["harness_exec"],
                                name_b="All Harness Trace Executions",
                                skip_start=True)
        plot_with_other_compare(ax5, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["harness_exec_agent_success"], "+A",
                                divide=lambda stats: stats["errors"]["harness_exec"],
                                skip_start=True,
                                twin=twin, log=False, no_total=True)
        ax5.set_title("Harness Execution Success Rate")
        plot_with_other_compare(ax6, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["bit_exec_success"], "Bit Exec Success",
                                divide=lambda stats: stats["errors"]["bit_exec"],
                                selector_b=lambda stats: stats["errors"]["bit_exec"],
                                name_b="All Bit Trace Executions",
                                skip_start=True)
        ax6.set_title("Bit-Level Trace Execution Success Rate (for MakeMess. and ReadMess.)")
        plot_with_other_compare(ax7, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["mm_exec_success"], "MM Exec Success",
                                divide=lambda stats: stats["errors"]["mm_exec"],
                                selector_b=lambda stats: stats["errors"]["mm_exec"],
                                name_b="All MM Trace Executions",
                                skip_start=True)
        ax7.set_title("Focus-Bit-Level Trace Execution Success Rate (for MakeMess. and ReadMess.)")
        plot_with_other_compare(ax8, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["corpus_exec_minimal"], "Min+Succ Corpus Exec",
                                divide=lambda stats: stats["errors"]["corpus_exec"],
                                selector_b=lambda stats: stats["errors"]["corpus_exec"],
                                name_b="Corpus Executions",
                                skip_start=True)
        ax8.set_title("Minimal and Successful Corpus Executions")

        # ERRORS SECTION
        plt.figtext(0.1, VS, "Error Analysis", fontsize=FS, ha='left', va='top')
        figErrors, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 20))
        plot_with_other_compare(ax1, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["put_error"], "Put Error",
                                divide=lambda stats: stats["errors"]["all_exec"], no_total=True)
        ax1.set_title("Put Error Rate")
        plot_with_other_compare(ax2, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["term_error"], "Term Error",
                                divide=lambda stats: stats["errors"]["all_exec"], no_total=True)
        ax2.set_title("Term Error Rate")

        twin = plot_with_other_compare(ax3, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["fn_error"], "Fn Error",
                                divide=lambda stats: stats["errors"]["all_exec"], no_total=True)
        # ax3.set_title("Function Error Rate")
        twin = plot_with_other_compare(ax3, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["term_bug_error"], "Term Bug Error",
                                divide=lambda stats: stats["errors"]["all_exec"], no_total=True,
                                twin=twin, log=False)
        # ax3.set_title("Term Bug Error Rate")
        plot_with_other_compare(ax3, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["codec_error"], "Codec Error",
                                divide=lambda stats: stats["errors"]["all_exec"], no_total=True,
                                twin=twin, log=False)
        # ax3.set_title("Codec Error Rate")
        ax3.set_title("Codec+TermBug+Fn Error Rate")
        twin = plot_with_other_compare(ax4, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["io_error"], "IO Error",
                                divide=lambda stats: stats["errors"]["all_exec"], no_total=True)
        # ax4.set_title("I/O Error Rate")
        twin = plot_with_other_compare(ax4, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["agent_error"], "Agent Error",
                                divide=lambda stats: stats["errors"]["all_exec"], no_total=True,
                                twin=twin)
        # ax4.set_title("Agent Error Rate")
        twin = plot_with_other_compare(ax4, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["stream_error"], "Stream Error",
                                divide=lambda stats: stats["errors"]["all_exec"], no_total=True,
                                twin=twin)
        # ax4.set_title("Stream Error Rate")
        plot_with_other_compare(ax4, times1, data1, times2, data2,
                                lambda stats: stats["errors"]["extraction_error"], "Extraction Error",
                                divide=lambda stats: stats["errors"]["all_exec"], no_total=True,
                                twin=twin)
        # ax4.set_title("Extraction Error Rate")
        ax4.set_title("Extraction+Stream+IO+Agent Error Rate")

        # Performance details
        plt.figtext(0.1, VS, "Performance Analysis", fontsize=FS, ha='left', va='top')
        figPerf, ((ax1, ax2), (ax3, ax4), (ax5, ax6)) = plt.subplots(3, 2, figsize=(12, 20))
        plot_with_other_compare(ax1, times1, data1, times2, data2, lambda stats: stats["intro"]["scheduler"],
                                "Sched Perf")
        ax1.set_title("Scheduler Performance")
        plot_with_other_compare(ax2, times1, data1, times2, data2, lambda stats: stats["intro"]["manager"],
                                "Manager Perf")
        ax2.set_title("Manager Performance")
        plot_with_other_compare(ax3, times1, data1, times2, data2,
                                lambda stats: stats["intro"]["introspect_features"]["mutate"],
                                "Mut Perf")
        ax3.set_title("Mutation Performance")
        plot_with_other_compare(ax4, times1, data1, times2, data2,
                                lambda stats: stats["intro"]["introspect_features"]["target_execution"],
                                "PUT Perf")
        ax4.set_title("PUT Performance")
        plot_with_other_compare(ax5, times1, data1, times2, data2, lambda stats: stats["intro"]["elapsed_cycles"],
                                "Cycles")
        ax5.set_title("Elapsed Cycles")

        ax6.set_visible(False)  # Hide the last subplot

        # Traces and Terms
        plt.figtext(0.1, VS, "Term, Trace, Payload Size Analysis", fontsize=FS, ha='left', va='top')
        figSizes, ((ax1, ax2), (ax3, ax4), (ax5, ax6), (ax7, ax8), (ax9, ax10), (ax11, ax12)) = plt.subplots(6, 2,
                                                                                                             figsize=(
                                                                                                                 12,
                                                                                                                 20))

        plot_with_other_compare(ax1, times1, data1, times2, data2, lambda stats: stats["trace"]["mean_trace_length"],
                                "Mean Trace Len",
                                smooth=True)
        ax1.set_title("Mean Trace Length")
        plot_with_other_compare(ax2, times1, data1, times2, data2, lambda stats: stats["trace"]["min_trace_length"],
                                "Min Trace Len")
        ax2.set_title("Minimum Trace Length")
        plot_with_other_compare(ax3, times1, data1, times2, data2, lambda stats: stats["trace"]["max_trace_length"],
                                "Max Trace Len")
        ax3.set_title("Maximum Trace Length")
        plot_with_other_compare(ax4, times1, data1, times2, data2, lambda stats: stats["trace"]["mean_term_size"],
                                "Mean Term Size",
                                smooth=True)
        ax4.set_title("Mean Term Size")
        plot_with_other_compare(ax5, times1, data1, times2, data2, lambda stats: stats["trace"]["min_term_size"],
                                "Min Term Size")
        ax5.set_title("Minimum Term Size")
        plot_with_other_compare(ax6, times1, data1, times2, data2, lambda stats: stats["trace"]["max_term_size"],
                                "Max Term Size")
        ax6.set_title("Maximum Term Size")

        plot_with_other_compare(ax7, times1, data1, times2, data2, lambda stats: stats["trace"]["mean_nb_payload"],
                                "Mean # Payloads")
        ax7.set_title("Mean Number of Payloads")
        plot_with_other_compare(ax8, times1, data1, times2, data2, lambda stats: stats["trace"]["max_nb_payload"],
                                "Max # Payloads")
        ax8.set_title("Maximum Number of Payloads")
        plot_with_other_compare(ax9, times1, data1, times2, data2, lambda stats: stats["trace"]["mean_payload_size"],
                                "Mean Payload Size")
        ax9.set_title("Mean Payloads Size")
        plot_with_other_compare(ax10, times1, data1, times2, data2, lambda stats: stats["trace"]["min_payload_size"],
                                "Min Payload Size")
        ax10.set_title("Minimum Payloads Size")
        plot_with_other_compare(ax11, times1, data1, times2, data2, lambda stats: stats["trace"]["max_payload_size"],
                                "Max Payload Size")
        ax11.set_title("Maximum Payloads Size")
        ax12.set_visible(False)  # Hide the last subplot

        ## Set plots sizes
        figGlobal.set_size_inches(20, 2.5, forward=True)
        figGlobal.tight_layout(pad=1)
        figCorpus.set_size_inches(20, 4, forward=True)
        figCorpus.tight_layout(pad=1)
        figFailure.set_size_inches(20, 7, forward=True)
        figFailure.tight_layout(pad=1)
        figErrors.set_size_inches(20, 4, forward=True)
        figErrors.tight_layout(pad=1)
        figPerf.set_size_inches(20, 6, forward=True)
        figPerf.tight_layout(pad=1)
        figSizes.set_size_inches(20, 20, forward=True)
        figSizes.tight_layout(pad=1)
        return [
            figGlobal,
            figFailure,
            figErrors,
            figPerf,
            figSizes
        ]


def plot_compare_exp(puffin_path, experiment1, experiment2, specific=1, client_id=1, cache=False):
    (start_date1, client_stats1, global_stats1) = extract_logs(puffin_path, experiment1, num=1, client_id=client_id,
                                                               cache=cache)
    (start_date2, client_stats2, global_stats2) = extract_logs(puffin_path, experiment2, num=2, client_id=client_id,
                                                               cache=cache)
    _ = plot_compare_stats(start_date1, client_stats1, global_stats1, start_date2, client_stats2, global_stats2)

    plt.show()


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

def plot_exp(puffin_path, experiment, specific=1, client_id=1):
    experiments_path = puffin_path + "experiments"
    (start_date, client_stats, global_stats) = extract_logs(experiment, client_id=client_id)
    # start_date_log = global_stats[0]["time"]

    fig = plot_stats(start_date, client_stats, global_stats)

    fig.set_size_inches(12, 14, forward=True)
    fig.tight_layout(pad=1)
    plt.show()

