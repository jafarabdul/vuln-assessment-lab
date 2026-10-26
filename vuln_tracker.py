#!/usr/bin/env python3
import argparse
import csv
import re
from collections import Counter
from datetime import date, timedelta

SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180, "Unknown": 90}
CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})")

FIELDS = [
    "host", "port", "protocol", "service", "version", "cve", "cvss",
    "severity", "first_seen", "due_date", "status", "breach",
    "days_overdue", "notes",
]

def severity_from_cvss(cvss):
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"

def parse_nmap_text(txt_path):
    rows = {}
    current_ip = "127.0.0.1"
    current_port = ""
    current_proto = "tcp"
    current_service = ""
    current_version = ""

    with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "Nmap scan report for" in line:
                parts = line.split()
                if parts:
                    current_ip = parts[-1].strip("()")
            elif "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 2:
                    port_proto = parts[0].split("/")
                    current_port = port_proto[0]
                    current_proto = port_proto[1] if len(port_proto) > 1 else "tcp"
                    state = parts[1]
                    if state == "open":
                        current_service = parts[2] if len(parts) > 2 else ""
                        current_version = " ".join(parts[3:]) if len(parts) > 3 else ""
            
            match_cve = CVE_RE.search(line)
            if match_cve and current_port:
                cve = match_cve.group(1)
                # Cari angka desimal sebagai skor CVSS di baris yang sama
                cvss = ""
                words = line.split()
                for w in words:
                    try:
                        val = float(w)
                        if 0.0 <= val <= 10.0:
                            cvss = str(val)
                            break
                    except ValueError:
                        continue
                
                key = (current_ip, current_port, current_proto, cve)
                rows[key] = {
                    "host": current_ip,
                    "port": current_port,
                    "protocol": current_proto,
                    "service": current_service,
                    "version": current_version,
                    "cve": cve,
                    "cvss": cvss,
                    "severity": severity_from_cvss(cvss),
                }
    return rows

def load_tracker(path):
    try:
        with open(path, newline="", encoding="utf-8") as f:
            return {
                (r["host"], r["port"], r["protocol"], r["cve"]): r
                for r in csv.DictReader(f)
            }
    except FileNotFoundError:
        return {}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("txt", help="file hasil nmap -oN")
    ap.add_argument("-o", "--output", default="tracker.csv")
    ap.add_argument("--as-of")
    args = ap.parse_args()

    today = date.fromisoformat(args.as_of) if args.as_of else date.today()
    old = load_tracker(args.output)
    new = parse_nmap_text(args.txt)

    merged = {}
    for key, row in new.items():
        prev = old.get(key)
        if prev:
            row["first_seen"] = prev["first_seen"]
            row["status"] = prev["status"]
            row["notes"] = prev["notes"]
            if not row["cvss"] and prev.get("cvss"):
                row["cvss"] = prev["cvss"]
                row["severity"] = severity_from_cvss(row["cvss"])
        else:
            row["first_seen"] = today.isoformat()
            row["status"] = "Open"
            row["notes"] = ""
        merged[key] = row

    for key, prev in old.items():
        if key not in merged:
            if prev["status"] == "Open":
                prev["status"] = "Resolved (not in latest scan)"
            merged[key] = prev

    for row in merged.values():
        first = date.fromisoformat(row["first_seen"])
        due = first + timedelta(days=SLA_DAYS.get(row["severity"], 90))
        overdue = (today - due).days
        is_open = row["status"] == "Open"
        row["due_date"] = due.isoformat()
        row["breach"] = "YES" if is_open and overdue > 0 else "NO"
        row["days_overdue"] = max(overdue, 0) if is_open else 0

    ordered = sorted(merged.values(), key=lambda r: float(r["cvss"]) if r["cvss"] else 0, reverse=True)

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(ordered)

    print(f"Total temuan terdeteksi: {len(ordered)}")
    print(f"Tersimpan di: {args.output}")

if __name__ == "__main__":
    main()
