#!/usr/bin/env .venv/bin/python3
"""
plot_list_stats.py — Bar charts of the per-list-type metrics in stats.json.

Usage:
    ./plot_list_stats.py [stats.json] [-o output.svg] [--at SECS] [--min-lists N]
                         [--executable]

The output format follows the -o extension (.svg .pdf .png). Prefer .svg: its
labels stay real text, so they can be selected, searched and restyled.

By default this is an end-of-run snapshot, summed over the last record of every
client (the counters are cumulative, so the last one is the run total):

  * length distribution — one panel per list type, the share of that type's
    lists falling in each power-of-two length bucket (0, 1, 2, 4 ... >=1024).
  * element diversity   — (# distinct elements) / (# elements), per list type,
    both pooled over all elements and averaged over lists.

--evolution instead follows one metric across the campaign, one panel per list
type, and is the view to compare a change to list generation or mutation
against:

    ./plot_list_stats.py stats.json --evolution -o length.svg
    ./plot_list_stats.py stats.json --evolution --metric diversity -o div.svg

Each panel carries two lines. "run to date" is the counter as it stands, an
average over every list since t=0 -- by the second half of a run it is so
damped that a real change barely moves it. "per interval" differences the
counters over a trailing --window, so it shows what the fuzzer is producing
*now*; that is the line to read. The two separating is itself the signal that
behaviour has shifted since the start.

--executable restricts every view to the lists of steps that were actually
executed (those before the step the trace failed at), i.e. the
`per_type_executable` section of stats.json instead of `per_type`.

The end-of-run numbers are printed as a table either way, which is also the
accessible view of the figure.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from matplotlib.patches import Patch, PathPatch
from matplotlib.path import Path

# Keep SVG labels as <text> rather than the glyph outlines matplotlib emits by
# default, so they stay selectable and searchable. Matplotlib writes the whole
# font stack down to a generic `sans-serif`, so the file still renders on a
# machine without DejaVu Sans -- only the metrics it was laid out against shift.
plt.rcParams["svg.fonttype"] = "none"

# ── Palette ───────────────────────────────────────────────────────────────────
# Categorical slots 1 and 2 of the validated default palette; the rest is ink.
SURFACE = "#fcfcfb"
SERIES_1 = "#2a78d6"  # blue
SERIES_2 = "#eb6834"  # orange
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#d8d7d2"

# Radius of a bar's rounded data end, in points. The ~2pt gap between adjacent
# bars comes out of the bar widths at the call sites instead.
BAR_RADIUS_PT = 3.0


# ── Data model ────────────────────────────────────────────────────────────────


@dataclass
class ListType:
    """The accumulated metrics of one list type, summed over clients."""

    name: str
    lists: int = 0
    nonempty: int = 0
    elements: int = 0
    distinct: int = 0
    ratio_permille: int = 0
    histogram: list[int] = field(default_factory=list)

    def add(self, other: dict) -> None:
        self.lists += other.get("lists", 0)
        self.elements += other.get("elements", 0)
        self.distinct += other.get("distinct", 0)
        self.nonempty += other.get("nonempty", 0)
        # Summing the raw numerator and denominator, rather than the per-client
        # rate, is what keeps a client that saw a million lists from weighing the
        # same as one that saw ten.
        self.ratio_permille += other.get("ratio_permille", 0)
        histogram = other.get("length_histogram", [])
        if not self.histogram:
            self.histogram = [0] * len(histogram)
        for i, count in enumerate(histogram):
            self.histogram[i] += count

    @property
    def mean_length(self) -> float:
        return self.elements / self.lists if self.lists else 0.0

    @property
    def pooled_diversity(self) -> float:
        return self.distinct / self.elements if self.elements else 0.0

    @property
    def mean_diversity(self) -> float:
        return self.ratio_permille / self.nonempty / 1000 if self.nonempty else 0.0

    @property
    def shares(self) -> list[float]:
        """The histogram as a share of this type's lists, in percent."""
        return [100 * c / self.lists if self.lists else 0.0 for c in self.histogram]


# ── Streaming parser ──────────────────────────────────────────────────────────


def iter_records(path: str, chunk_size: int = 65_536):
    """Stream-parse the concatenated-JSON stats file and yield every record."""
    decoder = json.JSONDecoder()
    buffer = ""
    with open(path, "r") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            buffer += chunk
            while True:
                buffer = buffer.lstrip()
                if not buffer:
                    break
                try:
                    record, end = decoder.raw_decode(buffer)
                except json.JSONDecodeError:
                    break  # incomplete record; wait for the next chunk
                buffer = buffer[end:]
                yield record


def record_epoch(r: dict) -> float:
    return r["time"]["secs_since_epoch"] + r["time"]["nanos_since_epoch"] / 1e9


def stats_key(executable: bool) -> str:
    """The `lists` section of stats.json to read."""
    return "per_type_executable" if executable else "per_type"


def collect(
    path: str, at: float | None, executable: bool = False
) -> tuple[dict[str, ListType], list[int]]:
    """Sum the last snapshot of every client into one entry per list type."""
    t0: float | None = None
    latest: dict[int, dict] = {}
    labels: list[int] = []

    for record in iter_records(path):
        if record.get("type") != "client":
            continue
        epoch = record_epoch(record)
        if t0 is None:
            t0 = epoch
        if at is not None and epoch - t0 > at:
            continue
        lists = record.get("lists")
        if not lists:
            continue
        labels = lists.get("length_bucket_labels", labels)
        latest[record.get("id")] = lists

    per_type: dict[str, ListType] = {}
    for lists in latest.values():
        for name, stats in lists.get(stats_key(executable), {}).items():
            per_type.setdefault(name, ListType(name)).add(stats)
    return per_type, labels


# ── Evolution over the campaign ───────────────────────────────────────────────

# The counters the evolution view differences. The histogram is left out: it is
# the snapshot view's subject, and carrying 12 more numbers per sample would
# dominate the timeline for no gain here.
FIELDS = ("lists", "nonempty", "elements", "distinct", "ratio_permille")

# One sample of one list type: the elapsed second, and the global totals then.
Sample = tuple[float, dict[str, int]]


@dataclass
class Line:
    """One line of an evolution panel: a ratio of two of the `FIELDS`."""

    label: str
    color: str
    numerator: str
    denominator: str
    cumulative: bool
    scale: float = 1.0


METRIC_LINES: dict[str, list[Line]] = {
    "length": [
        Line("per interval", SERIES_1, "elements", "lists", False),
        Line("run to date", SERIES_2, "elements", "lists", True),
    ],
    "diversity": [
        Line("pooled (per element)", SERIES_1, "distinct", "elements", False),
        Line("mean (per list)", SERIES_2, "ratio_permille", "nonempty", False, 1 / 1000),
    ],
}
METRIC_AXIS = {"length": "Mean length (elements)", "diversity": "Diversity"}
METRIC_TITLE = {
    "length": "Mean list length over the campaign",
    "diversity": "Element diversity over the campaign",
}


def collect_series(
    path: str, at: float | None, executable: bool = False
) -> dict[str, list[Sample]]:
    """Global per-type cumulative totals, sampled at every client report.

    Clients report independently, so the global total at any instant is the sum
    over each client's most recent snapshot. That sum is maintained incrementally
    rather than recomputed per record, which is what keeps a long multi-core run
    from going quadratic.
    """
    t0: float | None = None
    contribution: dict[int, dict[str, dict[str, int]]] = {}
    running: dict[str, dict[str, int]] = {}
    series: dict[str, list[Sample]] = {}

    for record in iter_records(path):
        if record.get("type") != "client":
            continue
        epoch = record_epoch(record)
        if t0 is None:
            t0 = epoch
        elapsed = epoch - t0
        if at is not None and elapsed > at:
            continue
        lists = record.get("lists")
        if not lists:
            continue

        client = record.get("id")
        fresh = {
            name: {f: stats.get(f, 0) for f in FIELDS}
            for name, stats in lists.get(stats_key(executable), {}).items()
        }
        stale = contribution.get(client, {})
        for name in set(stale) | set(fresh):
            totals = running.setdefault(name, dict.fromkeys(FIELDS, 0))
            before, after = stale.get(name), fresh.get(name)
            for f in FIELDS:
                totals[f] += (after[f] if after else 0) - (before[f] if before else 0)
        contribution[client] = fresh

        for name, totals in running.items():
            series.setdefault(name, []).append((elapsed, dict(totals)))

    return series


def ratio_series(
    samples: list[Sample], line: Line, window: float
) -> tuple[list[float], list[float | None]]:
    """`line`'s ratio at each sample, run-to-date or over the trailing `window`.

    Every counter is cumulative, so a run-to-date ratio averages over every list
    seen since t=0 and is heavily damped by the time a run is under way -- a
    change to the mutator barely registers. Differencing against an earlier
    sample gives the ratio over just that stretch, which is what the fuzzer is
    producing *now*. Numerator and denominator are differenced and only then
    divided, so a window holding few lists cannot outweigh one holding many.

    The window is in seconds rather than samples because the two rates are
    unrelated: `--stats-interval` (milliseconds) sets how often a record is
    written, and the stage re-fires the per-type stats once a second. Records
    written faster than that carry identical values, so differencing against the
    previous *sample* would yield mostly empty windows.
    """
    xs: list[float] = []
    ys: list[float | None] = []
    start = 0
    for elapsed, totals in samples:
        xs.append(elapsed)
        if line.cumulative:
            num, den = totals[line.numerator], totals[line.denominator]
        else:
            # Advance to the newest sample at or before the window's start. The
            # samples are ordered, so the pointer only ever moves forward.
            cutoff = elapsed - window
            while start + 1 < len(samples) and samples[start + 1][0] <= cutoff:
                start += 1
            base_elapsed, base = samples[start]
            if base_elapsed > cutoff:
                ys.append(None)  # the run is not yet a full window old
                continue
            num = totals[line.numerator] - base[line.numerator]
            den = totals[line.denominator] - base[line.denominator]
        # A negative delta means a client restarted and reset its counters.
        ys.append(num / den * line.scale if den > 0 and num >= 0 else None)
    return xs, ys


def default_window(series: dict[str, list[Sample]]) -> float:
    """A trailing window that stays readable whatever the run's length.

    A twentieth of the run, floored at 15s so a short run does not dissolve into
    per-sample noise, and capped at 5min so a long one keeps some resolution.
    """
    end = max((samples[-1][0] for samples in series.values()), default=0.0)
    return min(max(end / 20, 15.0), 300.0)


def fmt_elapsed(seconds: float, _=None) -> str:
    """Elapsed seconds as H:MM:SS, for axis ticks."""
    total = int(seconds)
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}"


# ── Marks ─────────────────────────────────────────────────────────────────────


def rounded_bars(ax, values, positions, width, *, horizontal, color) -> None:
    """Draw bars whose data-end is rounded and whose baseline end is square."""
    # The radius is in points, so it has to cross into data units per axis.
    figure = ax.figure
    figure.canvas.draw()
    bbox = ax.get_window_extent()
    dpi_scale = figure.dpi / 72
    axis_px = bbox.width if horizontal else bbox.height
    axis_span = (
        (ax.get_xlim()[1] - ax.get_xlim()[0])
        if horizontal
        else (ax.get_ylim()[1] - ax.get_ylim()[0])
    )
    per_point = axis_span / axis_px * dpi_scale if axis_px else 0

    for value, position in zip(values, positions):
        length = abs(value)
        if length == 0:
            continue
        radius = min(BAR_RADIUS_PT * per_point, length, width / 2)
        low, high = position - width / 2, position + width / 2
        # Along the bar: baseline at 0, data end at `value`.
        near, far = 0.0, value
        inner = far - radius if far > 0 else far + radius

        def point(along, across):
            return (along, across) if horizontal else (across, along)

        vertices = [
            point(near, low),
            point(inner, low),
            point(far, low),  # control
            point(far, low + radius),
            point(far, high - radius),
            point(far, high),  # control
            point(inner, high),
            point(near, high),
            point(near, low),
        ]
        codes = [
            Path.MOVETO,
            Path.LINETO,
            Path.CURVE3,
            Path.CURVE3,
            Path.LINETO,
            Path.CURVE3,
            Path.CURVE3,
            Path.LINETO,
            Path.CLOSEPOLY,
        ]
        ax.add_patch(PathPatch(Path(vertices, codes), facecolor=color, linewidth=0))


def style(ax) -> None:
    """Recessive grid and axes: the data is the only heavy ink."""
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=TEXT_SECONDARY, labelsize=8, length=3)
    ax.title.set_color(TEXT_PRIMARY)


# ── Plotting ──────────────────────────────────────────────────────────────────


def plot(
    per_type: dict[str, ListType],
    labels: list[int],
    output: str | None,
    dpi: int,
) -> None:
    types = sorted(per_type.values(), key=lambda t: -t.lists)
    ncols = min(3, len(types))
    nrows = (len(types) + ncols - 1) // ncols

    # One row of panels is 2.6in; the diversity panel needs 0.3in per bar on top of its chrome.
    panel_height = 2.6
    diversity_height = 0.3 * len(types) + 1.4
    figure = plt.figure(
        figsize=(4.0 * ncols, panel_height * nrows + diversity_height + 0.8)
    )
    figure.patch.set_facecolor(SURFACE)
    grid = figure.add_gridspec(
        nrows + 1, ncols, height_ratios=[panel_height] * nrows + [diversity_height]
    )

    tick_labels = [str(label) for label in labels]
    if tick_labels:
        tick_labels[-1] = f"≥{tick_labels[-1]}"

    for index, list_type in enumerate(types):
        ax = figure.add_subplot(grid[index // ncols, index % ncols])
        style(ax)
        shares = list_type.shares
        positions = list(range(len(shares)))
        ax.set_xlim(-0.6, len(shares) - 0.4)
        ax.set_ylim(0, max(max(shares, default=0) * 1.18, 1))
        ax.set_xticks(positions, tick_labels, rotation=45, ha="right")
        ax.yaxis.set_major_formatter(mticker.PercentFormatter(decimals=0))
        ax.grid(True, axis="y", color=GRID, alpha=0.5, linewidth=0.6)
        ax.set_axisbelow(True)
        # A 2pt surface gap between adjacent bars, taken out of the slot width.
        rounded_bars(
            ax, shares, positions, 0.82, horizontal=False, color=SERIES_1
        )
        # Direct-label only the buckets that carry the distribution.
        for position, share in zip(positions, shares):
            if share >= 5:
                ax.annotate(
                    f"{share:.0f}%",
                    xy=(position, share),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    fontsize=7,
                    color=TEXT_SECONDARY,
                )
        ax.set_title(list_type.name, fontsize=10, pad=14)
        ax.text(
            0.0,
            1.02,
            f"{list_type.lists:,} lists · mean length {list_type.mean_length:.1f}",
            transform=ax.transAxes,
            fontsize=7.5,
            color=TEXT_SECONDARY,
        )
        if index % ncols == 0:
            ax.set_ylabel("Share of lists", fontsize=8, color=TEXT_SECONDARY)
        if index // ncols == nrows - 1:
            ax.set_xlabel("Length bucket", fontsize=8, color=TEXT_SECONDARY)

    ax = figure.add_subplot(grid[nrows, :])
    style(ax)
    positions = list(range(len(types)))
    ax.set_ylim(-0.6, len(types) - 0.4)
    ax.set_xlim(0, 1.14)
    ax.set_yticks(positions, [t.name for t in types])
    ax.invert_yaxis()
    ax.grid(True, axis="x", color=GRID, alpha=0.5, linewidth=0.6)
    ax.set_axisbelow(True)
    handles: list[Patch] = []
    for offset, color, label, value in (
        (-0.19, SERIES_1, "pooled (per element)", lambda t: t.pooled_diversity),
        (0.19, SERIES_2, "mean (per list)", lambda t: t.mean_diversity),
    ):
        values = [value(t) for t in types]
        rounded_bars(
            ax,
            values,
            [p + offset for p in positions],
            0.32,
            horizontal=True,
            color=color,
        )
        # Two series, so both are direct-labeled as well as legended.
        for position, v in zip(positions, values):
            ax.annotate(
                f"{v:.2f}",
                xy=(v, position + offset),
                xytext=(4, 0),
                textcoords="offset points",
                va="center",
                fontsize=7,
                color=TEXT_SECONDARY,
            )
        handles.append(Patch(facecolor=color, label=label))
    # Two series: legended above the panel, and direct-labeled on every bar.
    ax.legend(
        handles=handles,
        fontsize=8,
        frameon=False,
        ncol=2,
        loc="lower right",
        bbox_to_anchor=(1, 1.0),
        labelcolor=TEXT_SECONDARY,
    )
    ax.set_title(
        "Element diversity — distinct elements / elements", fontsize=10, loc="left"
    )
    ax.set_xlabel("Diversity (1.0 = every element distinct)", fontsize=8, color=TEXT_SECONDARY)

    figure.suptitle("List generation and mutation — per list type", fontsize=13, color=TEXT_PRIMARY)
    figure.tight_layout(rect=(0, 0, 1, 0.98))

    if output:
        figure.savefig(output, dpi=dpi, bbox_inches="tight", facecolor=SURFACE)
        print(f"Saved → {output}")
    else:
        plt.show()


def plot_evolution(
    series: dict[str, list[Sample]],
    metric: str,
    window: float,
    output: str | None,
    dpi: int,
) -> None:
    """One panel per list type, `metric` over elapsed campaign time."""
    types = sorted(series, key=lambda name: -series[name][-1][1]["lists"])
    lines = METRIC_LINES[metric]
    ncols = min(3, len(types))
    nrows = (len(types) + ncols - 1) // ncols

    figure = plt.figure(figsize=(4.0 * ncols, 2.5 * nrows + 0.9))
    figure.patch.set_facecolor(SURFACE)
    end = max(samples[-1][0] for samples in series.values())

    for index, name in enumerate(types):
        ax = figure.add_subplot(nrows, ncols, index + 1)
        style(ax)
        samples = series[name]
        ax.set_xlim(0, max(end, 1))
        if metric == "diversity":
            ax.set_ylim(0, 1.08)
        ax.grid(True, color=GRID, alpha=0.5, linewidth=0.6)
        ax.set_axisbelow(True)
        ax.xaxis.set_major_formatter(mticker.FuncFormatter(fmt_elapsed))
        ax.tick_params(axis="x", labelrotation=45)
        for label in ax.get_xticklabels():
            label.set_horizontalalignment("right")

        for line in lines:
            xs, ys = ratio_series(samples, line, window)
            ax.plot(xs, ys, color=line.color, linewidth=1.4, label=line.label)
            # Direct-label the last known value, so identity is never colour alone.
            last = next(
                (i for i in range(len(ys) - 1, -1, -1) if ys[i] is not None), None
            )
            if last is not None:
                ax.annotate(
                    f"{ys[last]:.3g}",
                    xy=(xs[last], ys[last]),
                    xytext=(4, 0),
                    textcoords="offset points",
                    va="center",
                    fontsize=7,
                    color=line.color,
                    clip_on=False,
                )

        ax.set_title(name, fontsize=10, pad=14)
        ax.text(
            0.0,
            1.02,
            f"{samples[-1][1]['lists']:,} lists",
            transform=ax.transAxes,
            fontsize=7.5,
            color=TEXT_SECONDARY,
        )
        if index % ncols == 0:
            ax.set_ylabel(METRIC_AXIS[metric], fontsize=8, color=TEXT_SECONDARY)
        if index // ncols == nrows - 1:
            ax.set_xlabel("Elapsed (H:MM:SS)", fontsize=8, color=TEXT_SECONDARY)

    figure.suptitle(
        f"{METRIC_TITLE[metric]} — interval series over a "
        f"{fmt_elapsed(window)} trailing window",
        fontsize=13,
        color=TEXT_PRIMARY,
    )
    figure.legend(
        handles=[Patch(facecolor=l.color, label=l.label) for l in lines],
        fontsize=8,
        frameon=False,
        ncol=len(lines),
        loc="upper right",
        labelcolor=TEXT_SECONDARY,
    )
    figure.tight_layout(rect=(0, 0, 1, 0.97))

    if output:
        figure.savefig(output, dpi=dpi, bbox_inches="tight", facecolor=SURFACE)
        print(f"Saved → {output}")
    else:
        plt.show()


def print_table(per_type: dict[str, ListType], labels: list[int]) -> None:
    """The table view of the figure."""
    types = sorted(per_type.values(), key=lambda t: -t.lists)
    width = max((len(t.name) for t in types), default=4)
    header = f"{'list type':<{width}}  {'lists':>10} {'mean len':>9} {'pooled':>7} {'mean':>6}"
    print(header)
    print("-" * len(header))
    for t in types:
        print(
            f"{t.name:<{width}}  {t.lists:>10,} {t.mean_length:>9.2f} "
            f"{t.pooled_diversity:>7.3f} {t.mean_diversity:>6.3f}"
        )
    print()
    buckets = "  ".join(f"{label:>7}" for label in labels)
    print(f"{'length histogram':<{width}}  {buckets}")
    print("-" * len(header))
    for t in types:
        counts = "  ".join(f"{count:>7,}" for count in t.histogram)
        print(f"{t.name:<{width}}  {counts}")


# ── Entry point ───────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("input", nargs="?", default="stats.json")
    p.add_argument("-o", "--output", help="Save the figure instead of showing it")
    p.add_argument("--dpi", type=int, default=150)
    p.add_argument(
        "--at",
        metavar="SECS",
        type=float,
        default=None,
        help="Snapshot the counters as of this many elapsed seconds (default: end of run)",
    )
    p.add_argument(
        "--min-lists",
        type=int,
        default=1,
        help="Drop list types seen fewer times than this (default: 1)",
    )
    p.add_argument(
        "-x",
        "--executable",
        action="store_true",
        help="Only count the lists of executed steps (per_type_executable in stats.json)",
    )
    p.add_argument(
        "-e",
        "--evolution",
        action="store_true",
        help="Plot the metric over campaign time instead of the end-of-run snapshot",
    )
    p.add_argument(
        "--metric",
        choices=sorted(METRIC_LINES),
        default="length",
        help="With --evolution, which metric to follow (default: length)",
    )
    p.add_argument(
        "--window",
        type=float,
        default=None,
        metavar="SECS",
        help="With --evolution, the trailing window each interval point averages "
        "over (default: a twentieth of the run, within 15s..5min)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.window is not None and args.window <= 0:
        print("--window must be positive", file=sys.stderr)
        sys.exit(2)

    per_type, labels = collect(args.input, args.at, args.executable)
    per_type = {n: t for n, t in per_type.items() if t.lists >= args.min_lists}

    if not per_type:
        print(
            f"No list stats in {args.input}: the fuzzer must be built with the "
            "`introspection` feature.",
            file=sys.stderr,
        )
        sys.exit(1)

    # The table is the end-of-run state either way, and the figure's table view.
    print_table(per_type, labels)

    if args.evolution:
        series = collect_series(args.input, args.at, args.executable)
        series = {n: s for n, s in series.items() if n in per_type and s}
        window = args.window or default_window(series)
        plot_evolution(series, args.metric, window, args.output, args.dpi)
    else:
        plot(per_type, labels, args.output, args.dpi)


if __name__ == "__main__":
    main()
