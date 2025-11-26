#!/usr/bin/env python3
"""
Robust Log Analyzer
- Generates a valid sample log if file missing or contains no parseable entries
- Uses regex parsing for reliability
- Case-insensitive --level and --keyword matching
- Prints diagnostics so you can see why results are empty (if they are)
"""

import argparse
import re
from datetime import datetime, timedelta
import random
import os
import sys

LEVELS = ["INFO", "WARNING", "ERROR"]
LOG_REGEX = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(INFO|WARNING|ERROR)\] (.+)$")

SAMPLE_MESSAGES = [
    "System started",
    "User logged in",
    "High CPU usage detected",
    "Service restarted",
    "Connection failed",
    "Unexpected error occurred",
    "Memory threshold exceeded",
    "Background task completed",
    "File not found",
    "Network timeout",
    "Authentication failed",
    "Permission denied",
    "Disk space low",
    "Configuration loaded",
]


def generate_sample_log(file_path, lines=50):
    """Create a sample log with EXACTLY the format the parser expects."""
    print(f"[+] Creating sample log: {file_path} ({lines} lines)")
    base = datetime.now() - timedelta(days=3)
    with open(file_path, "w", encoding="utf-8") as f:
        for _ in range(lines):
            ts = base + timedelta(minutes=random.randint(1, 5000))
            level = random.choice(LEVELS)
            msg = random.choice(SAMPLE_MESSAGES)
            f.write(f"{ts.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {msg}\n")


def read_and_parse(file_path):
    """Read file, return tuple (all_lines, parsed_entries) where parsed_entries is a list of (dt, level, message, raw)."""
    all_lines = []
    parsed = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.rstrip("\n")
                all_lines.append(line)
                m = LOG_REGEX.match(line)
                if m:
                    ts_str, level, msg = m.groups()
                    try:
                        ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                        parsed.append((ts, level, msg, line))
                    except ValueError:
                        # skip malformed timestamp
                        continue
    except FileNotFoundError:
        return None, None
    return all_lines, parsed


def analyze(parsed_entries, level=None, keyword=None, start_date=None, end_date=None):
    """Filter parsed entries according to provided filters. Returns matching raw lines and stats."""
    matches = []
    level_counts = {l: 0 for l in LEVELS}
    for ts, lvl, msg, raw in parsed_entries:
        # filters
        if level and lvl.upper() != level.upper():
            continue
        if keyword and keyword.lower() not in msg.lower():
            continue
        if start_date and ts < start_date:
            continue
        if end_date and ts > end_date:
            continue
        matches.append(raw)
        if lvl in level_counts:
            level_counts[lvl] += 1
    return matches, level_counts


def main():
    parser = argparse.ArgumentParser(description="Robust Log Analyzer")
    parser.add_argument("file", help="Path to log file (will be created if missing or invalid)")
    parser.add_argument("--level", help="Filter by level (INFO, WARNING, ERROR)")
    parser.add_argument("--keyword", help="Filter by keyword in message")
    parser.add_argument("--start", help="Start date inclusive (YYYY-MM-DD)")
    parser.add_argument("--end", help="End date inclusive (YYYY-MM-DD)")
    args = parser.parse_args()

    # parse optional dates
    start_date = None
    end_date = None
    try:
        if args.start:
            start_date = datetime.strptime(args.start, "%Y-%m-%d")
        if args.end:
            # include whole end day by adding 23:59:59
            end_date = datetime.strptime(args.end, "%Y-%m-%d") + timedelta(hours=23, minutes=59, seconds=59)
    except ValueError as e:
        print("[!] Date parse error:", e)
        sys.exit(1)

    # read & parse
    all_lines, parsed = read_and_parse(args.file)

    # If file missing -> generate sample and read again
    if all_lines is None:
        generate_sample_log(args.file, lines=60)
        all_lines, parsed = read_and_parse(args.file)

    # If file exists but parsed is empty -> regenerate sample and re-read (fixes bad formats / empty files)
    if parsed is not None and len(parsed) == 0:
        print(f"[!] No parseable entries found in '{args.file}'. Regenerating sample file to correct format.")
        generate_sample_log(args.file, lines=60)
        all_lines, parsed = read_and_parse(args.file)

    # If still nothing, show diagnostic and exit
    if parsed is None or len(parsed) == 0:
        print(f"[!] Error: no parseable log entries found in '{args.file}' after attempts to fix.")
        if all_lines is not None:
            print(f"File contains {len(all_lines)} raw lines (showing first 10):")
            for i, l in enumerate(all_lines[:10], start=1):
                print(f"{i:02d}: {l!r}")
        sys.exit(1)

    # perform analysis (case-insensitive level handled in analyze)
    matches, counts = analyze(parsed, level=args.level, keyword=args.keyword, start_date=start_date, end_date=end_date)

    # output diagnostics + results
    print("\n=== DIAGNOSTICS ===")
    print(f"Total raw lines in file : {len(all_lines)}")
    print(f"Total parseable entries  : {len(parsed)} (format: YYYY-MM-DD HH:MM:SS [LEVEL] message)")
    print(f"Total matched after filters: {len(matches)}\n")

    print("Log Level Counts (in file):")
    for lvl in LEVELS:
        print(f"  {lvl}: {counts.get(lvl, 0)}")
    print()

    if args.keyword:
        print(f"Keyword filter: '{args.keyword}'")
    if args.level:
        print(f"Level filter : '{args.level.upper()}'")
    if start_date or end_date:
        print(f"Date range   : {args.start or '-'} to {args.end or '-'}")
    print("\n=== MATCHING LINES ===")
    if matches:
        for line in matches:
            print(line)
    else:
        print("(no lines matched the provided filters)")

if __name__ == "__main__":
    main()
