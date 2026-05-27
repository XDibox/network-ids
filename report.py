#!/usr/bin/env python3
"""
IDS Alert Report Generator
Parses ids_alerts.log and prints a structured summary.
Usage: python3 report.py [--log FILE] [--since YYYY-MM-DD] [--export FILE]
"""

import re
import argparse
from collections import defaultdict
from datetime import datetime, date

from colorama import Fore, Style, init

init(autoreset=True)

# Matches lines like:
# 2026-05-26 22:29:15,123 | ERROR | HIGH | PORT SCAN | 192.168.1.5 | description
_LOG_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    r'[,\d]* \| \w+ \| '
    r'(?P<severity>LOW|MEDIUM|HIGH|CRITICAL) \| '
    r'(?P<category>[^|]+?) \| '
    r'(?P<src>[^|]+?) \| '
    r'(?P<desc>.+)$'
)

_SEV_COLOR = {
    'LOW':      Fore.YELLOW,
    'MEDIUM':   Fore.LIGHTYELLOW_EX,
    'HIGH':     Fore.RED,
    'CRITICAL': Fore.MAGENTA,
}


def parse_log(log_file: str, since: date | None = None) -> list[dict]:
    entries = []
    try:
        with open(log_file, encoding='utf-8') as f:
            for line in f:
                m = _LOG_RE.match(line.strip())
                if not m:
                    continue
                ts = datetime.strptime(m['ts'], '%Y-%m-%d %H:%M:%S')
                if since and ts.date() < since:
                    continue
                entries.append({
                    'ts':       ts,
                    'severity': m['severity'].strip(),
                    'category': m['category'].strip(),
                    'src':      m['src'].strip(),
                    'desc':     m['desc'].strip(),
                })
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Log file not found: {log_file}{Style.RESET_ALL}")
    return entries


def _bar(count: int, total: int, width: int = 30) -> str:
    filled = int(width * count / total) if total else 0
    return '█' * filled + '░' * (width - filled)


def _section(title: str):
    print(f"\n{Fore.CYAN}{'─'*64}")
    print(f"  {title}")
    print(f"{'─'*64}{Style.RESET_ALL}")


def print_report(entries: list[dict], export_path: str | None = None):
    if not entries:
        print(f"{Fore.YELLOW}[!] No entries found.{Style.RESET_ALL}")
        return

    total = len(entries)
    lines = []

    def out(text: str = ''):
        print(text)
        lines.append(re.sub(r'\x1b\[[0-9;]*m', '', text))

    # ── Header ────────────────────────────────────────────────────────────────
    first = entries[0]['ts'].strftime('%Y-%m-%d %H:%M')
    last  = entries[-1]['ts'].strftime('%Y-%m-%d %H:%M')
    out(f"\n{Fore.CYAN}{'═'*64}")
    out(f"  IDS ALERT REPORT  |  {first}  →  {last}")
    out(f"{'═'*64}{Style.RESET_ALL}")

    # ── Severity summary ──────────────────────────────────────────────────────
    sev_counts: dict = defaultdict(int)
    for e in entries:
        sev_counts[e['severity']] += 1

    _section('SEVERITY SUMMARY')
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        count = sev_counts.get(sev, 0)
        color = _SEV_COLOR[sev]
        bar   = _bar(count, total)
        out(f"  {color}{sev:<10}{Style.RESET_ALL}  {bar}  {count:>4}  ({count/total*100:.1f}%)")
    out(f"\n  Total alerts: {total}")

    # ── Top attacking IPs ─────────────────────────────────────────────────────
    ip_counts: dict = defaultdict(int)
    ip_sevs:   dict = defaultdict(set)
    ip_cats:   dict = defaultdict(set)
    for e in entries:
        ip_counts[e['src']] += 1
        ip_sevs[e['src']].add(e['severity'])
        ip_cats[e['src']].add(e['category'])

    _section('TOP ATTACKING IPs')
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    for ip, count in top_ips:
        worst = next(s for s in ('CRITICAL','HIGH','MEDIUM','LOW') if s in ip_sevs[ip])
        color = _SEV_COLOR[worst]
        bar   = _bar(count, top_ips[0][1])
        cats  = ', '.join(sorted(ip_cats[ip]))
        out(f"  {color}{ip:<20}{Style.RESET_ALL}  {bar}  {count:>4}  [{cats}]")

    # ── Attack type breakdown ─────────────────────────────────────────────────
    cat_counts: dict = defaultdict(int)
    for e in entries:
        cat_counts[e['category']] += 1

    _section('ATTACK TYPE BREAKDOWN')
    top_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
    for cat, count in top_cats:
        bar = _bar(count, total)
        out(f"  {cat:<25}  {bar}  {count:>4}")

    # ── Hourly timeline ───────────────────────────────────────────────────────
    hourly: dict = defaultdict(int)
    for e in entries:
        hourly[e['ts'].strftime('%Y-%m-%d %H:00')] += 1

    _section('HOURLY TIMELINE')
    peak = max(hourly.values()) if hourly else 1
    for hour in sorted(hourly):
        count = hourly[hour]
        bar   = _bar(count, peak, width=20)
        out(f"  {hour}  {bar}  {count}")

    # ── Critical events detail ────────────────────────────────────────────────
    criticals = [e for e in entries if e['severity'] == 'CRITICAL']
    if criticals:
        _section(f'CRITICAL EVENTS ({len(criticals)})')
        for e in criticals:
            ts = e['ts'].strftime('%Y-%m-%d %H:%M:%S')
            out(f"  {Fore.MAGENTA}{ts}  {e['category']:<20}  {e['src']:<18}  {e['desc']}{Style.RESET_ALL}")

    out(f"\n{Fore.CYAN}{'═'*64}{Style.RESET_ALL}\n")

    # ── Export ────────────────────────────────────────────────────────────────
    if export_path:
        with open(export_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        print(f"{Fore.GREEN}[+] Report exported to: {export_path}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description='IDS Alert Report Generator')
    parser.add_argument('--log',    default='ids_alerts.log', help='Log file to parse')
    parser.add_argument('--since',  default=None, help='Filter from date (YYYY-MM-DD)')
    parser.add_argument('--export', default=None, help='Export plain-text report to file')
    args = parser.parse_args()

    since = None
    if args.since:
        try:
            since = date.fromisoformat(args.since)
        except ValueError:
            print(f"{Fore.RED}[!] Invalid date format. Use YYYY-MM-DD.{Style.RESET_ALL}")
            return

    entries = parse_log(args.log, since)
    print_report(entries, args.export)


if __name__ == '__main__':
    main()
