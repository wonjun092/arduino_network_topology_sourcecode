from __future__ import annotations

import argparse
import csv
import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


LOG_RE = re.compile(r"^(S|R|F|E|W),")
ATTEMPT_RE = re.compile(r"attempted_seq\s*=\s*(\d+)\.\.(\d+)")


@dataclass
class LogRecord:
    kind: str
    time: int
    values: list[int]
    raw: str


@dataclass
class NodeLog:
    path: Path
    topology: str
    node: int
    role: str
    records: list[LogRecord]
    attempted_min: int | None
    attempted_max: int | None


def parse_node_log(path: Path) -> NodeLog:
    records: list[LogRecord] = []
    attempted_min = None
    attempted_max = None
    topology = path.name.split("_node", 1)[0]
    node_match = re.search(r"_node(\d+)_", path.name)
    node = int(node_match.group(1)) if node_match else -1
    role = "sender" if "sender" in path.name else "receiver"

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = ATTEMPT_RE.search(line)
            if m:
                attempted_min = int(m.group(1))
                attempted_max = int(m.group(2))
            continue
        if not LOG_RE.match(line):
            continue
        parts = line.split(",")
        kind = parts[0]
        try:
            time = int(parts[1])
            values = [int(p) for p in parts[2:] if p != ""]
        except ValueError:
            continue
        records.append(LogRecord(kind=kind, time=time, values=values, raw=line))

    return NodeLog(
        path=path,
        topology=topology,
        node=node,
        role=role,
        records=records,
        attempted_min=attempted_min,
        attempted_max=attempted_max,
    )


def pair_fault_windows(records: Iterable[LogRecord]) -> list[tuple[int, int, int]]:
    """Return (start_time, end_time, node) windows paired from E/W logs."""
    starts: dict[int, list[int]] = defaultdict(list)
    windows: list[tuple[int, int, int]] = []
    for rec in sorted(records, key=lambda r: r.time):
        if rec.kind not in {"E", "W"} or not rec.values:
            continue
        node = rec.values[0]
        if rec.kind == "E":
            starts[node].append(rec.time)
        else:
            if starts[node]:
                start = starts[node].pop(0)
                windows.append((start, rec.time, node))
    return windows


def in_windows(time: int, windows: list[tuple[int, int, int]]) -> bool:
    return any(start <= time <= end for start, end, _ in windows)


def estimate_timing(send_by_seq: dict[int, LogRecord], attempted_max: int) -> tuple[float, float]:
    """Estimate send interval and intercept for missing S logs."""
    seqs = sorted(send_by_seq)
    if len(seqs) < 2:
        return 100.0, 0.0

    intervals: list[float] = []
    for a, b in zip(seqs, seqs[1:]):
        if b != a:
            intervals.append((send_by_seq[b].time - send_by_seq[a].time) / (b - a))
    interval = statistics.median(intervals) if intervals else 100.0
    intercepts = [send_by_seq[s].time - s * interval for s in seqs]
    intercept = statistics.median(intercepts)
    return interval, intercept


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else math.nan


def stdev(values: list[float]) -> float:
    return statistics.pstdev(values) if len(values) >= 2 else 0.0 if len(values) == 1 else math.nan


def percentile(values: list[float], p: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    idx = (len(ordered) - 1) * p
    lo = math.floor(idx)
    hi = math.ceil(idx)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] * (hi - idx) + ordered[hi] * (idx - lo)


def max_consecutive_loss(packet_rows: list[dict]) -> int:
    max_run = 0
    current = 0
    for row in sorted(packet_rows, key=lambda r: r["seq"]):
        if row["status"] != "success":
            current += 1
            max_run = max(max_run, current)
        else:
            current = 0
    return max_run


def loss_burst_count(packet_rows: list[dict]) -> int:
    bursts = 0
    prev_loss = False
    for row in sorted(packet_rows, key=lambda r: r["seq"]):
        is_loss = row["status"] != "success"
        if is_loss and not prev_loss:
            bursts += 1
        prev_loss = is_loss
    return bursts


def first_after(records: Iterable[LogRecord], kind: str, time: int) -> int | None:
    candidates = [r.time for r in records if r.kind == kind and r.time >= time]
    return min(candidates) if candidates else None


def analyze_topology(sender: NodeLog, receiver: NodeLog) -> tuple[dict, list[dict], list[dict]]:
    send_by_seq = {r.values[1]: r for r in sender.records if r.kind == "S" and len(r.values) >= 3}
    recv_by_seq = {r.values[1]: r for r in receiver.records if r.kind == "R" and len(r.values) >= 3}

    attempted_min = sender.attempted_min or 1
    attempted_max = sender.attempted_max or max(send_by_seq.keys() | recv_by_seq.keys())
    interval, intercept = estimate_timing(send_by_seq, attempted_max)

    sender_windows = pair_fault_windows(sender.records)
    receiver_windows = pair_fault_windows(receiver.records)
    endpoint_windows = sender_windows + receiver_windows

    packet_rows: list[dict] = []
    for seq in range(attempted_min, attempted_max + 1):
        expected_send_time = int(round(intercept + seq * interval))
        s = send_by_seq.get(seq)
        r = recv_by_seq.get(seq)
        send_time = s.time if s else expected_send_time
        recv_time = r.time if r else None

        if s is None:
            status = "sender_fault_no_send" if in_windows(expected_send_time, sender_windows) else "no_send_unknown"
            loss_cause = status
            latency = math.nan
        elif r is not None:
            status = "success"
            loss_cause = ""
            latency = r.time - s.time
        elif in_windows(send_time, receiver_windows):
            status = "receiver_fault_loss"
            loss_cause = "receiver_fault_loss"
            latency = math.nan
        else:
            status = "inferred_hidden_or_network_loss"
            loss_cause = "inferred_hidden_or_network_loss"
            latency = math.nan

        packet_rows.append(
            {
                "topology": sender.topology,
                "seq": seq,
                "expected_send_time": expected_send_time,
                "send_time": s.time if s else "",
                "recv_time": r.time if r else "",
                "latency_ms": "" if math.isnan(latency) else latency,
                "status": status,
                "loss_cause": loss_cause,
            }
        )

    successes = [r for r in packet_rows if r["status"] == "success"]
    visible_sent = [r for r in packet_rows if r["send_time"] != ""]
    attempted = len(packet_rows)
    recv_n = len(successes)
    sent_n = len(visible_sent)
    latencies = [float(r["latency_ms"]) for r in successes]
    status_counts = Counter(r["status"] for r in packet_rows)
    loss_counts = Counter(r["loss_cause"] for r in packet_rows if r["loss_cause"])

    normal_rows = [
        r
        for r in packet_rows
        if r["send_time"] != "" and not in_windows(int(r["send_time"]), endpoint_windows)
    ]
    normal_sent = len(normal_rows)
    normal_recv = sum(1 for r in normal_rows if r["status"] == "success")

    endpoint_fault_rows = [
        r
        for r in packet_rows
        if in_windows(int(r["expected_send_time"]), endpoint_windows)
        or (r["send_time"] != "" and in_windows(int(r["send_time"]), endpoint_windows))
    ]
    endpoint_fault_sent = sum(1 for r in endpoint_fault_rows if r["send_time"] != "")
    endpoint_fault_recv = sum(1 for r in endpoint_fault_rows if r["status"] == "success")

    hidden_loss_n = loss_counts["inferred_hidden_or_network_loss"]
    receiver_fault_loss_n = loss_counts["receiver_fault_loss"]
    sender_fault_no_send_n = loss_counts["sender_fault_no_send"]

    resume_times_after_receiver_w: list[int] = []
    for _start, end, _node in receiver_windows:
        next_r = first_after(receiver.records, "R", end)
        if next_r is not None:
            resume_times_after_receiver_w.append(next_r - end)

    resume_times_after_sender_w: list[int] = []
    for _start, end, _node in sender_windows:
        next_s = first_after(sender.records, "S", end)
        if next_s is not None:
            resume_times_after_sender_w.append(next_s - end)

    duration_sec = (max([r["expected_send_time"] for r in packet_rows]) - min([r["expected_send_time"] for r in packet_rows])) / 1000
    throughput = recv_n / duration_sec if duration_sec > 0 else math.nan

    # A compact reliability score. It is only for comparison, not a physical law.
    pdr_visible = recv_n / sent_n * 100 if sent_n else math.nan
    end_to_end = recv_n / attempted * 100 if attempted else math.nan
    pdr_normal = normal_recv / normal_sent * 100 if normal_sent else math.nan
    pdr_endpoint_fault = endpoint_fault_recv / endpoint_fault_sent * 100 if endpoint_fault_sent else math.nan
    recovery_sender = mean(resume_times_after_sender_w)
    recovery_receiver = mean(resume_times_after_receiver_w)

    summary = {
        "topology": sender.topology,
        "attempted_packets": attempted,
        "visible_sent_packets": sent_n,
        "received_packets": recv_n,
        "end_to_end_success_rate_pct": end_to_end,
        "visible_pdr_pct": pdr_visible,
        "normal_visible_pdr_pct": pdr_normal,
        "endpoint_fault_pdr_pct": pdr_endpoint_fault,
        "packet_loss_rate_visible_pct": 100 - pdr_visible if not math.isnan(pdr_visible) else math.nan,
        "sender_fault_no_send_count": sender_fault_no_send_n,
        "receiver_fault_loss_count": receiver_fault_loss_n,
        "inferred_hidden_or_network_loss_count": hidden_loss_n,
        "avg_latency_ms": mean(latencies),
        "std_latency_ms": stdev(latencies),
        "min_latency_ms": min(latencies) if latencies else math.nan,
        "max_latency_ms": max(latencies) if latencies else math.nan,
        "p95_latency_ms": percentile(latencies, 0.95),
        "max_consecutive_loss_packets": max_consecutive_loss(packet_rows),
        "loss_burst_count": loss_burst_count(packet_rows),
        "avg_loss_burst_length_packets": (attempted - recv_n) / loss_burst_count(packet_rows)
        if loss_burst_count(packet_rows)
        else 0,
        "estimated_max_outage_ms": max_consecutive_loss(packet_rows) * interval,
        "throughput_recv_per_sec": throughput,
        "sender_resume_time_ms_avg": recovery_sender,
        "receiver_resume_time_ms_avg": recovery_receiver,
    }

    loss_rows = [
        {"topology": sender.topology, "loss_cause": k, "count": v}
        for k, v in sorted(loss_counts.items())
    ]

    return summary, packet_rows, loss_rows


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def clean_num(value: float | int | str) -> float:
    if value == "" or value is None:
        return math.nan
    try:
        return float(value)
    except ValueError:
        return math.nan


def fmt(value: float) -> str:
    if math.isnan(value):
        return "n/a"
    if abs(value - round(value)) < 1e-9:
        return str(int(round(value)))
    return f"{value:.1f}"


def svg_text(x: float, y: float, text: str, size: int = 12, anchor: str = "middle", weight: str = "normal") -> str:
    safe = (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    return f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" font-size="{size}" font-weight="{weight}">{safe}</text>'


def write_svg(path: Path, width: int, height: int, body: list[str]) -> None:
    header = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style>",
        "text{font-family:Arial,'Malgun Gothic',sans-serif;fill:#1f2933}",
        ".axis{stroke:#34495e;stroke-width:1}",
        ".grid{stroke:#d7dee8;stroke-width:1}",
        ".muted{fill:#607080}",
        "</style>",
        '<rect width="100%" height="100%" fill="white"/>',
    ]
    path.write_text("\n".join(header + body + ["</svg>\n"]), encoding="utf-8")


def nice_max(values: list[float], minimum: float = 1.0) -> float:
    vals = [v for v in values if not math.isnan(v)]
    if not vals:
        return minimum
    m = max(max(vals), minimum)
    if m <= 10:
        step = 1
    elif m <= 50:
        step = 5
    elif m <= 100:
        step = 10
    elif m <= 500:
        step = 50
    else:
        step = 100
    return math.ceil(m / step) * step


def grouped_bar_svg(path: Path, title: str, categories: list[str], series: list[tuple[str, list[float], str]], y_label: str, y_max: float | None = None) -> None:
    width, height = 920, 500
    left, right, top, bottom = 78, 30, 56, 86
    plot_w, plot_h = width - left - right, height - top - bottom
    ymax = y_max if y_max is not None else nice_max([v for _, vals, _ in series for v in vals])
    body: list[str] = [svg_text(width / 2, 28, title, 18, weight="bold")]
    for i in range(6):
        yval = ymax * i / 5
        y = top + plot_h - (yval / ymax) * plot_h
        body.append(f'<line class="grid" x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}"/>')
        body.append(svg_text(left - 10, y + 4, fmt(yval), 11, anchor="end"))
    body.append(f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}"/>')
    body.append(f'<line class="axis" x1="{left}" y1="{top+plot_h}" x2="{width-right}" y2="{top+plot_h}"/>')
    body.append(svg_text(18, top + plot_h / 2, y_label, 12, anchor="middle"))
    n_cat = len(categories)
    group_w = plot_w / n_cat
    bar_w = min(28, group_w / (len(series) + 1.2))
    for ci, cat in enumerate(categories):
        cx = left + group_w * (ci + 0.5)
        body.append(svg_text(cx, top + plot_h + 25, cat, 12))
        for si, (_name, values, color) in enumerate(series):
            v = values[ci]
            h = 0 if math.isnan(v) else (v / ymax) * plot_h
            x = cx - (len(series) * bar_w) / 2 + si * bar_w
            y = top + plot_h - h
            body.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w-2:.1f}" height="{h:.1f}" fill="{color}"/>')
            if not math.isnan(v):
                body.append(svg_text(x + (bar_w - 2) / 2, y - 4, fmt(v), 9))
    lx = left
    ly = height - 26
    for name, _values, color in series:
        body.append(f'<rect x="{lx}" y="{ly-11}" width="14" height="14" fill="{color}"/>')
        body.append(svg_text(lx + 20, ly, name, 11, anchor="start"))
        lx += 185
    write_svg(path, width, height, body)


def stacked_bar_svg(path: Path, title: str, categories: list[str], series: list[tuple[str, list[float], str]], y_label: str) -> None:
    width, height = 920, 500
    left, right, top, bottom = 78, 30, 56, 90
    plot_w, plot_h = width - left - right, height - top - bottom
    totals = [sum(0 if math.isnan(vals[i]) else vals[i] for _name, vals, _color in series) for i in range(len(categories))]
    ymax = nice_max(totals)
    body: list[str] = [svg_text(width / 2, 28, title, 18, weight="bold")]
    for i in range(6):
        yval = ymax * i / 5
        y = top + plot_h - (yval / ymax) * plot_h
        body.append(f'<line class="grid" x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}"/>')
        body.append(svg_text(left - 10, y + 4, fmt(yval), 11, anchor="end"))
    body.append(f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}"/>')
    body.append(f'<line class="axis" x1="{left}" y1="{top+plot_h}" x2="{width-right}" y2="{top+plot_h}"/>')
    body.append(svg_text(18, top + plot_h / 2, y_label, 12))
    group_w = plot_w / len(categories)
    bar_w = min(62, group_w * 0.55)
    for ci, cat in enumerate(categories):
        cx = left + group_w * (ci + 0.5)
        y_cursor = top + plot_h
        for name, vals, color in series:
            v = vals[ci]
            h = 0 if math.isnan(v) else (v / ymax) * plot_h
            y_cursor -= h
            body.append(f'<rect x="{cx-bar_w/2:.1f}" y="{y_cursor:.1f}" width="{bar_w:.1f}" height="{h:.1f}" fill="{color}"/>')
            if h > 18:
                body.append(svg_text(cx, y_cursor + h / 2 + 4, fmt(v), 10))
        body.append(svg_text(cx, top + plot_h + 25, cat, 12))
    lx, ly = left, height - 48
    for name, _values, color in series:
        body.append(f'<rect x="{lx}" y="{ly-11}" width="14" height="14" fill="{color}"/>')
        body.append(svg_text(lx + 20, ly, name, 10, anchor="start"))
        lx += 210
        if lx > width - 230:
            lx = left
            ly += 22
    write_svg(path, width, height, body)


def bar_line_svg(path: Path, title: str, categories: list[str], bars: list[float], line: list[float], bar_label: str, line_label: str) -> None:
    width, height = 920, 500
    left, right, top, bottom = 78, 72, 56, 86
    plot_w, plot_h = width - left - right, height - top - bottom
    bar_ymax = nice_max(bars)
    line_ymax = nice_max(line)
    body = [svg_text(width / 2, 28, title, 18, weight="bold")]
    for i in range(6):
        yval = bar_ymax * i / 5
        y = top + plot_h - (yval / bar_ymax) * plot_h
        body.append(f'<line class="grid" x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}"/>')
        body.append(svg_text(left - 10, y + 4, fmt(yval), 11, anchor="end"))
        rval = line_ymax * i / 5
        body.append(svg_text(width - right + 10, y + 4, fmt(rval), 11, anchor="start"))
    body.append(f'<line class="axis" x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}"/>')
    body.append(f'<line class="axis" x1="{width-right}" y1="{top}" x2="{width-right}" y2="{top+plot_h}"/>')
    body.append(f'<line class="axis" x1="{left}" y1="{top+plot_h}" x2="{width-right}" y2="{top+plot_h}"/>')
    group_w = plot_w / len(categories)
    bar_w = min(62, group_w * 0.5)
    points = []
    for i, cat in enumerate(categories):
        cx = left + group_w * (i + 0.5)
        bh = 0 if math.isnan(bars[i]) else bars[i] / bar_ymax * plot_h
        body.append(f'<rect x="{cx-bar_w/2:.1f}" y="{top+plot_h-bh:.1f}" width="{bar_w:.1f}" height="{bh:.1f}" fill="#34495e"/>')
        body.append(svg_text(cx, top + plot_h + 25, cat, 12))
        lh = 0 if math.isnan(line[i]) else line[i] / line_ymax * plot_h
        points.append((cx, top + plot_h - lh))
    if len(points) >= 2:
        d = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        body.append(f'<polyline points="{d}" fill="none" stroke="#e74c3c" stroke-width="2"/>')
    for x, y in points:
        body.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="#e74c3c"/>')
    body.append(f'<rect x="{left}" y="{height-35}" width="14" height="14" fill="#34495e"/>')
    body.append(svg_text(left + 20, height - 24, bar_label, 11, anchor="start"))
    body.append(f'<line x1="{left+220}" y1="{height-28}" x2="{left+250}" y2="{height-28}" stroke="#e74c3c" stroke-width="2"/>')
    body.append(f'<circle cx="{left+235}" cy="{height-28}" r="4" fill="#e74c3c"/>')
    body.append(svg_text(left + 260, height - 24, line_label, 11, anchor="start"))
    write_svg(path, width, height, body)


def make_charts(summary_rows: list[dict], packet_rows: list[dict], out_dir: Path) -> None:
    chart_dir = out_dir / "charts"
    chart_dir.mkdir(parents=True, exist_ok=True)

    topo_order = ["BUS", "STAR", "RING", "TREE", "MESH"]
    rows_by_topo = {r["topology"]: r for r in summary_rows}
    topologies = [t for t in topo_order if t in rows_by_topo]

    visible = [clean_num(rows_by_topo[t]["visible_pdr_pct"]) for t in topologies]
    end2end = [clean_num(rows_by_topo[t]["end_to_end_success_rate_pct"]) for t in topologies]
    normal = [clean_num(rows_by_topo[t]["normal_visible_pdr_pct"]) for t in topologies]
    grouped_bar_svg(
        chart_dir / "01_pdr_comparison.svg",
        "Packet Delivery / Success Rate by Topology",
        topologies,
        [
            ("Visible PDR", visible, "#2980b9"),
            ("End-to-end success", end2end, "#27ae60"),
            ("Normal-window PDR", normal, "#f39c12"),
        ],
        "Percent (%)",
        100,
    )

    avg_lat = [clean_num(rows_by_topo[t]["avg_latency_ms"]) for t in topologies]
    p95_lat = [clean_num(rows_by_topo[t]["p95_latency_ms"]) for t in topologies]
    grouped_bar_svg(
        chart_dir / "02_latency_average_p95.svg",
        "Latency: Average and Tail Delay",
        topologies,
        [
            ("Average latency", avg_lat, "#3498db"),
            ("95th percentile", p95_lat, "#c0392b"),
        ],
        "Latency (ms)",
    )

    causes = [
        "sender_fault_no_send",
        "receiver_fault_loss",
        "inferred_hidden_or_network_loss",
        "no_send_unknown",
    ]
    colors = ["#7f8c8d", "#e67e22", "#8e44ad", "#bdc3c7"]
    stacked_series = []
    for cause, color in zip(causes, colors):
        counts = [
            sum(1 for r in packet_rows if r["topology"] == t and r["status"] == cause)
            for t in topologies
        ]
        stacked_series.append((cause, counts, color))
    stacked_bar_svg(
        chart_dir / "03_loss_cause_breakdown.svg",
        "Loss / Non-delivery Cause Breakdown",
        topologies,
        stacked_series,
        "Packet count",
    )

    max_loss = [clean_num(rows_by_topo[t]["max_consecutive_loss_packets"]) for t in topologies]
    outage = [clean_num(rows_by_topo[t]["estimated_max_outage_ms"]) for t in topologies]
    bar_line_svg(
        chart_dir / "04_continuity_outage.svg",
        "Communication Continuity Under Faults",
        topologies,
        max_loss,
        outage,
        "Max consecutive lost packets",
        "Estimated max outage (ms)",
    )

    sender_resume = [clean_num(rows_by_topo[t]["sender_resume_time_ms_avg"]) for t in topologies]
    receiver_resume = [clean_num(rows_by_topo[t]["receiver_resume_time_ms_avg"]) for t in topologies]
    grouped_bar_svg(
        chart_dir / "05_endpoint_recovery_resume_time.svg",
        "Endpoint Recovery Resume Time",
        topologies,
        [
            ("After sender W: next S", sender_resume, "#16a085"),
            ("After receiver W: next R", receiver_resume, "#d35400"),
        ],
        "Resume time (ms)",
    )

    for topo in topologies:
        rows = [r for r in packet_rows if r["topology"] == topo]
        success_seq = [int(r["seq"]) for r in rows if r["status"] == "success"]
        loss_seq = [int(r["seq"]) for r in rows if r["status"] != "success"]
        latency_seq = [int(r["seq"]) for r in rows if r["latency_ms"] != ""]
        latency = [float(r["latency_ms"]) for r in rows if r["latency_ms"] != ""]
        width, height = 980, 560
        left, right, top, bottom = 70, 35, 55, 60
        plot_w = width - left - right
        body = [svg_text(width / 2, 28, f"{topo}: Packet Timeline and Successful-Packet Latency", 18, weight="bold")]
        max_seq = max(int(r["seq"]) for r in rows)
        def sx(seq: int) -> float:
            return left + (seq - 1) / max(max_seq - 1, 1) * plot_w
        y_recv, y_loss = 120, 185
        body.append(svg_text(left - 10, y_recv + 4, "received", 11, anchor="end"))
        body.append(svg_text(left - 10, y_loss + 4, "lost/no-send", 11, anchor="end"))
        body.append(f'<line class="grid" x1="{left}" y1="{y_recv}" x2="{width-right}" y2="{y_recv}"/>')
        body.append(f'<line class="grid" x1="{left}" y1="{y_loss}" x2="{width-right}" y2="{y_loss}"/>')
        for s in success_seq:
            body.append(f'<circle cx="{sx(s):.1f}" cy="{y_recv}" r="3" fill="#27ae60"/>')
        for s in loss_seq:
            body.append(f'<circle cx="{sx(s):.1f}" cy="{y_loss}" r="4" fill="#c0392b"/>')
        lat_top, lat_h = 270, 210
        ymax = nice_max(latency)
        for i in range(5):
            yval = ymax * i / 4
            y = lat_top + lat_h - (yval / ymax) * lat_h
            body.append(f'<line class="grid" x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}"/>')
            body.append(svg_text(left - 8, y + 4, fmt(yval), 10, anchor="end"))
        points = [(sx(s), lat_top + lat_h - (v / ymax) * lat_h) for s, v in zip(latency_seq, latency)]
        if len(points) >= 2:
            body.append('<polyline points="' + " ".join(f"{x:.1f},{y:.1f}" for x, y in points) + '" fill="none" stroke="#2980b9" stroke-width="2"/>')
        for x0, y0 in points:
            body.append(f'<circle cx="{x0:.1f}" cy="{y0:.1f}" r="2.5" fill="#2980b9"/>')
        body.append(svg_text(20, lat_top + lat_h / 2, "latency (ms)", 11))
        body.append(f'<line class="axis" x1="{left}" y1="{lat_top+lat_h}" x2="{width-right}" y2="{lat_top+lat_h}"/>')
        for tick in [1, max_seq // 4, max_seq // 2, max_seq * 3 // 4, max_seq]:
            body.append(svg_text(sx(tick), lat_top + lat_h + 22, tick, 10))
        body.append(svg_text(width / 2, height - 18, "packet sequence", 12))
        write_svg(chart_dir / f"timeline_{topo}.svg", width, height, body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze Arduino CAN topology serial rawdata txt files.")
    parser.add_argument(
        "--input-dir",
        default="outputs/serial_rawdata_examples_v2_endpoint_errors",
        help="Directory containing *_sender_serial.txt and *_receiver_serial.txt files.",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs/topology_analysis_results",
        help="Directory for CSV summaries and charts.",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logs = [parse_node_log(p) for p in sorted(input_dir.glob("*.txt"))]
    by_topology: dict[str, dict[str, NodeLog]] = defaultdict(dict)
    for log in logs:
        by_topology[log.topology][log.role] = log

    summary_rows: list[dict] = []
    packet_rows: list[dict] = []
    loss_rows: list[dict] = []
    for topology in sorted(by_topology):
        pair = by_topology[topology]
        if "sender" not in pair or "receiver" not in pair:
            continue
        summary, packets, losses = analyze_topology(pair["sender"], pair["receiver"])
        summary_rows.append(summary)
        packet_rows.extend(packets)
        loss_rows.extend(losses)

    # Stable ordering for easier report use.
    order = {"BUS": 0, "STAR": 1, "RING": 2, "TREE": 3, "MESH": 4}
    summary_rows.sort(key=lambda r: order.get(r["topology"], 99))
    packet_rows.sort(key=lambda r: (order.get(r["topology"], 99), int(r["seq"])))
    loss_rows.sort(key=lambda r: (order.get(r["topology"], 99), r["loss_cause"]))

    write_csv(output_dir / "summary_metrics.csv", summary_rows)
    write_csv(output_dir / "packet_level_analysis.csv", packet_rows)
    write_csv(output_dir / "loss_cause_summary.csv", loss_rows)
    make_charts(summary_rows, packet_rows, output_dir)

    print(f"Wrote {output_dir / 'summary_metrics.csv'}")
    print(f"Wrote {output_dir / 'packet_level_analysis.csv'}")
    print(f"Wrote {output_dir / 'loss_cause_summary.csv'}")
    print(f"Wrote charts to {output_dir / 'charts'}")


if __name__ == "__main__":
    main()
