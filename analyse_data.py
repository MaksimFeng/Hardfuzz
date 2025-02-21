"""
Generates four line charts 

1) breakpoints_line_time.png:   Cumulative breakpoints vs. time
2) coverage_line_time.png:      Def-use coverage fraction vs. time
3) breakpoints_line_round.png:  Cumulative breakpoints vs. round 
4) coverage_line_round.png:     Coverage fraction vs. round 

"""

import re
import logging as log
from datetime import datetime
import matplotlib.pyplot as plt

from config.settings import DEF_USE_FILE, LOG_FILE


def parse_def_use_file(filename):

    def_dict = {}
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        log.error(f"Definition-Use file '{filename}' not found.")
        return []

    i = 0
    while i < len(lines):
        if lines[i].startswith("Definition:"):
            def_line = lines[i]
            use_line = lines[i+1] if i+1 < len(lines) and lines[i+1].startswith("Use:") else None
            if use_line:
                def_addr_str = def_line.split()[-1]
                use_addr_str = use_line.split()[-1]
                if def_addr_str not in def_dict:
                    def_dict[def_addr_str] = []
                def_dict[def_addr_str].append(use_addr_str)
                i += 2
            else:
                i += 1
        else:
            i += 1

    # Return a list of tuples (def_addr, [use_addr, ...])
    sorted_defs = sorted(def_dict.items(), key=lambda x: len(x[1]), reverse=True)
    return sorted_defs

def count_total_def_use_edges(def_list):

    total_edges = 0
    for _, uses in def_list:
        total_edges += len(uses)
    return total_edges


ROUND_PATTERN = re.compile(r'Starting Round #(\d+)')
DEF_TRIGGER_PATTERN = re.compile(r'(.*?) - root - INFO - Def triggered => (0x[0-9A-Fa-f]+)')
USE_TRIGGER_PATTERN = re.compile(r'(.*?) - root - INFO - Use triggered => (0x[0-9A-Fa-f]+)')
DEFUSE_COV_PATTERN  = re.compile(r'Updating def-use coverage => def=(0x[0-9A-Fa-f]+), use=(0x[0-9A-Fa-f]+), idx=\d+')

def parse_logfile(log_path, total_def_use_edges):


    bp_timestamps = []
    coverage_pairs = set()
    coverage_events = []

    bp_per_round = {}
    cov_per_round = {}
    current_round = 0

    start_time = None
    current_coverage_count = 0

    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()

            round_match = ROUND_PATTERN.search(line)
            if round_match:
                current_round = int(round_match.group(1))
                if current_round not in bp_per_round:
                    bp_per_round[current_round] = 0
                if current_round not in cov_per_round:
                    cov_per_round[current_round] = 0.0
                continue

            def_match = DEF_TRIGGER_PATTERN.search(line)
            if def_match:
                time_str = def_match.group(1).strip()
                dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                if start_time is None:
                    start_time = dt
                bp_timestamps.append(dt)
                if current_round > 0:
                    bp_per_round[current_round] += 1
                continue


            use_match = USE_TRIGGER_PATTERN.search(line)
            if use_match:
                time_str = use_match.group(1).strip()
                dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                if start_time is None:
                    start_time = dt
                bp_timestamps.append(dt)
                if current_round > 0:
                    bp_per_round[current_round] += 1
                continue

            cov_match = DEFUSE_COV_PATTERN.search(line)
            if cov_match:
                time_str = line.split(" - ")[0].strip()
                dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                if start_time is None:
                    start_time = dt

                def_addr = cov_match.group(1)
                use_addr = cov_match.group(2)

                old_size = len(coverage_pairs)
                coverage_pairs.add((def_addr, use_addr))
                new_size = len(coverage_pairs)
                if new_size > old_size:
                    # coverage increment
                    current_coverage_count = new_size
                    elapsed_sec = (dt - start_time).total_seconds()
                    coverage_events.append((elapsed_sec, current_coverage_count))

                    fraction = current_coverage_count / total_def_use_edges if total_def_use_edges else 0
                    if current_round > 0:
                        cov_per_round[current_round] = fraction

    return bp_timestamps, coverage_events, bp_per_round, cov_per_round


def plot_breakpoints_over_time(bp_timestamps):

    if not bp_timestamps:
        print("No breakpoints found => skipping breakpoints_line_time.png")
        return

    bp_timestamps.sort()
    start = bp_timestamps[0]
    x_times = [(t - start).total_seconds() for t in bp_timestamps]
    y_counts = [i+1 for i in range(len(x_times))]

    fig1 = plt.figure(figsize=(8,4))
    plt.plot(x_times, y_counts, marker='o', color='blue', label='Breakpoints')
    plt.title("Breakpoints Over Time (Cumulative)")
    plt.xlabel("Time (seconds)")
    plt.ylabel("Cumulative Breakpoints")
    plt.grid(True)
    plt.legend()

    plt.savefig('breakpoints_line_time.png')
    print("Saved breakpoints_line_time.png")
    plt.show(block=False)
    plt.close(fig1)

def plot_coverage_over_time(coverage_events, total_def_use_edges):

    if not coverage_events:
        print("No coverage events => skipping coverage_line_time.png")
        return

    coverage_events.sort(key=lambda x: x[0])
    times = [x[0] for x in coverage_events]
    coverage_counts = [x[1] for x in coverage_events]
    coverage_fracs = [c/total_def_use_edges for c in coverage_counts] if total_def_use_edges > 0 else [0]*len(times)

    fig2 = plt.figure(figsize=(8,4))
    plt.plot(times, coverage_fracs, marker='o', color='green', label='Coverage fraction')
    plt.title("Def-Use Coverage Over Time")
    plt.xlabel("Time (seconds)")
    plt.ylabel("Coverage Fraction")
    plt.ylim([0,1.05])
    plt.grid(True)
    plt.legend()

    plt.savefig('coverage_line_time.png')
    print("Saved coverage_line_time.png")
    plt.show(block=False)
    plt.close(fig2)

def plot_breakpoints_vs_round(bp_per_round):
 
    if not bp_per_round:
        print("No round-based breakpoints => skipping breakpoints_line_round.png")
        return

    rounds_sorted = sorted(bp_per_round.keys())
    xvals = []
    yvals = []
    cumulative = 0
    for r in rounds_sorted:
        cumulative += bp_per_round[r]
        xvals.append(r)
        yvals.append(cumulative)

    fig3 = plt.figure(figsize=(8,4))
    plt.plot(xvals, yvals, marker='o', color='blue', label='Breakpoints (cumulative)')
    plt.title("Breakpoints vs. Round (Cumulative)")
    plt.xlabel("Round #")
    plt.ylabel("Cumulative Breakpoints")
    plt.grid(True)
    plt.legend()

    plt.savefig('breakpoints_line_round.png')
    print("Saved breakpoints_line_round.png")
    plt.show(block=False)
    plt.close(fig3)

def plot_coverage_vs_round(cov_per_round):

    if not cov_per_round:
        print("No round-based coverage => skipping coverage_line_round.png")
        return

    rounds_sorted = sorted(cov_per_round.keys())
    xvals = rounds_sorted
    yvals = [cov_per_round[r] for r in rounds_sorted]

    fig4 = plt.figure(figsize=(8,4))
    plt.plot(xvals, yvals, marker='o', color='green', label='Coverage fraction')
    plt.title("Coverage vs. Round")
    plt.xlabel("Round #")
    plt.ylabel("Coverage fraction")
    plt.ylim([0,1.05])
    plt.grid(True)
    plt.legend()

    plt.savefig('coverage_line_round.png')
    print("Saved coverage_line_round.png")
    plt.show(block=False)
    plt.close(fig4)


def main():
    def_use_list = parse_def_use_file(DEF_USE_FILE)
    total_def_use_edges = count_total_def_use_edges(def_use_list)
    print(f"Loaded {total_def_use_edges} def-use edges from {DEF_USE_FILE}.")

    bp_timestamps, coverage_events, bp_per_round, cov_per_round = parse_logfile(LOG_FILE, total_def_use_edges)
    print(f"Parsed {len(bp_timestamps)} total breakpoints from {LOG_FILE}.")
    print(f"Found {len(coverage_events)} coverage increments.")
    print(f"Rounds with breakpoints: {sorted(bp_per_round.keys())}")
    print(f"Rounds with coverage fraction: {sorted(cov_per_round.keys())}")

    # Time-based plots
    plot_breakpoints_over_time(bp_timestamps)
    plot_coverage_over_time(coverage_events, total_def_use_edges)

    # Round-based plots
    plot_breakpoints_vs_round(bp_per_round)
    plot_coverage_vs_round(cov_per_round)

if __name__ == "__main__":
    main()
