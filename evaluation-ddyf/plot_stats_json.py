#!/usr/bin/env .venv/bin/python3
"""
plot.py — Parse stats.json and plot global fuzzer statistics over time.

Usage:
    ./plot.py [stats.json] [-o output.png] [--start SECS] [--end SECS]

Time range examples (elapsed seconds from the first record):
    --end 3600              plot only the first hour
    --start 7200 --end 9000 plot between t=2h and t=2h30m

Adding new graphs
-----------------
Append a PlotConfig to the PLOTS list near the bottom of this file.
Each PlotConfig holds one or more Series, each defined by a display label
and an `extract` callable that receives a parsed global record (dict) and
returns a number.  Nested fields use normal dict access:

    Series("corpus_size", lambda r: r["corpus_size"])

The file is parsed incrementally — only global records are kept in memory.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Callable

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ── Data model ────────────────────────────────────────────────────────────────


@dataclass
class Series:
    """A single line on a subplot."""

    label: str
    extract: Callable[[dict], float]


@dataclass
class PlotConfig:
    """Everything needed to draw one subplot panel."""

    title: str
    ylabel: str
    series: list[Series] = field(default_factory=list)


# ── Plot definitions ──────────────────────────────────────────────────────────
# Add or remove PlotConfig entries here to control which panels are rendered.
# `extract` receives a global stats record dict and must return a numeric value.

PLOTS: list[PlotConfig] = [
    PlotConfig(
        title="Objectives & duplicates",
        ylabel="Number of traces",
        series=[
            Series("objective_size", lambda r: r["objective_size"]),
            Series("duplicate_size", lambda r: r["duplicates"]),
        ],
    ),
    PlotConfig(
        title="Corpus",
        ylabel="Number of traces",
        series=[
            Series("corpus_size", lambda r: r["corpus_size"]),
        ],
    ),
    PlotConfig(
        title="Duplicates proportion",
        ylabel="Proportion of duplicates",
        series=[
            Series(
                "Proportion",
                lambda r: (
                    r["duplicates"] / (r["objective_size"] + r["duplicates"])
                    if (r["objective_size"] + r["duplicates"]) > 0
                    else 0
                ),
            ),
        ],
    ),
]


# ── Streaming parser ──────────────────────────────────────────────────────────


def iter_global_records(path: str, chunk_size: int = 65_536):
    """
    Stream-parse a concatenated-JSON stats file and yield only 'global' records.

    The file is a sequence of bare JSON objects with no separator between them.
    We use JSONDecoder.raw_decode to consume one object at a time from a rolling
    string buffer so memory usage stays bounded regardless of file size.
    """
    decoder = json.JSONDecoder()
    buf = ""
    with open(path) as fh:
        while True:
            chunk = fh.read(chunk_size)
            buf += chunk
            pos = 0
            while pos < len(buf):
                # Skip any whitespace between objects.
                while pos < len(buf) and buf[pos] in " \t\n\r":
                    pos += 1
                if pos >= len(buf):
                    break
                try:
                    obj, end = decoder.raw_decode(buf, pos)
                    if obj.get("type") == "global":
                        yield obj
                    pos = end
                except json.JSONDecodeError:
                    # Incomplete object — need more data from file.
                    break
            buf = buf[pos:]  # discard already-consumed bytes
            if not chunk:  # EOF
                break


# ── Helpers ───────────────────────────────────────────────────────────────────


def record_epoch(r: dict) -> float:
    """Return the timestamp of a record as a float epoch second."""
    return r["time"]["secs_since_epoch"] + r["time"]["nanos_since_epoch"] / 1e9


def fmt_elapsed(seconds: float, _=None) -> str:
    """Format an elapsed-seconds value as H:MM:SS for axis tick labels."""
    s = int(seconds)
    h, remainder = divmod(s, 3600)
    m, s = divmod(remainder, 60)
    return f"{h}:{m:02d}:{s:02d}"


# ── Plotting ──────────────────────────────────────────────────────────────────


def plot(
    elapsed: list[float],
    series_data: list[list[list]],
    output: str | None,
    dpi: int,
    start: float,
    end: float,
) -> None:
    ncols = 1
    nrows = (len(PLOTS) + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(8, 6 * nrows), sharex=True)
    axes_flat = axes.flatten() if nrows > 1 else list(axes) if ncols > 1 else [axes]

    for i, (cfg, ax) in enumerate(zip(PLOTS, axes_flat)):
        for si, s in enumerate(cfg.series):
            (line,) = ax.plot(elapsed, series_data[i][si], label=s.label, linewidth=1)
            # Annotate the last non-None value at the right edge of the line.
            ys = series_data[i][si]
            last_idx = next(
                (j for j in range(len(ys) - 1, -1, -1) if ys[j] is not None), None
            )
            if last_idx is not None:
                ax.annotate(
                    f"{ys[last_idx]:.4g}",
                    xy=(elapsed[last_idx], ys[last_idx]),
                    xytext=(4, 0),
                    textcoords="offset points",
                    fontsize=8,
                    va="center",
                    color=line.get_color(),
                    clip_on=False,
                )
        ax.set_title(cfg.title)
        ax.set_ylabel(cfg.ylabel)
        if len(cfg.series) > 1:
            ax.legend(fontsize=8)
        ax.xaxis.set_major_formatter(mticker.FuncFormatter(fmt_elapsed))
        ax.xaxis.set_major_locator(mticker.AutoLocator())
        ax.xaxis.set_minor_locator(mticker.AutoMinorLocator())
        ax.yaxis.set_major_locator(mticker.AutoLocator())
        ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
        ax.set_xlim(start, end)
        ax.grid(True, which="major", alpha=0.4)
        ax.grid(True, which="minor", alpha=0.15)
        ax.tick_params(axis="both", which="major", length=5)
        ax.tick_params(axis="both", which="minor", length=3)

    # Hide any unused subplot slots.
    for ax in axes_flat[len(PLOTS) :]:
        ax.set_visible(False)

    # x-axis label only on the bottom row.
    for ax in axes_flat[len(PLOTS) - ncols : len(PLOTS)]:
        ax.set_xlabel(
            f"Elapsed time (H:MM:SS)  —  window {fmt_elapsed(start)} → {fmt_elapsed(end)}"
        )

    # fig.suptitle("tlspuffin — Global Fuzzing Stats", fontsize=14)
    plt.tight_layout()

    if output:
        fig.savefig(output, dpi=dpi, bbox_inches="tight")
        print(f"Saved → {output}")
    else:
        plt.show()


# ── Entry point ───────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "input",
        nargs="?",
        default="stats.json",
        help="Path to stats.json (default: stats.json)",
    )
    p.add_argument(
        "-o",
        "--output",
        help="Save figure to file instead of opening an interactive window "
        "(format inferred from extension: .png .pdf .svg)",
    )
    p.add_argument(
        "--dpi",
        type=int,
        default=150,
        help="Resolution for raster output (default: 150)",
    )
    p.add_argument(
        "--start",
        metavar="SECS",
        type=float,
        default=None,
        help="Start of the plotted window in elapsed seconds from t=0 (default: 0)",
    )
    p.add_argument(
        "--end",
        metavar="SECS",
        type=float,
        default=None,
        help="End of the plotted window in elapsed seconds from t=0 (default: full run)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    print(f"Parsing {args.input} …", end=" ", flush=True)

    t0: float | None = None
    elapsed: list[float] = []
    # series_data[plot_index][series_index] = list of values, one per record.
    series_data: list[list[list]] = [[[] for _ in cfg.series] for cfg in PLOTS]

    for record in iter_global_records(args.input):
        epoch = record_epoch(record)
        if t0 is None:
            t0 = epoch
        e = epoch - t0

        # Skip records outside the requested window.
        if args.start is not None and e < args.start:
            continue
        if args.end is not None and e > args.end:
            continue

        elapsed.append(e)
        for pi, cfg in enumerate(PLOTS):
            for si, s in enumerate(cfg.series):
                try:
                    series_data[pi][si].append(s.extract(record))
                except (KeyError, TypeError):
                    series_data[pi][si].append(None)

    print(f"{len(elapsed)} global records loaded.")

    if not elapsed:
        print("No global records found in the requested window.", file=sys.stderr)
        sys.exit(1)

    win_start = args.start if args.start is not None else elapsed[0]
    win_end = args.end if args.end is not None else elapsed[-1]

    plot(elapsed, series_data, args.output, args.dpi, win_start, win_end)


if __name__ == "__main__":
    main()
