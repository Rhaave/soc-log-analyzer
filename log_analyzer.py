#!/usr/bin/env python3
"""
SOC Log Analyzer
=================
Narzedzie do wykrywania podejrzanej aktywnosci w logach systemowych i webowych.
Symuluje pierwszy etap pracy analityka SOC L1: triage alertow bezpieczenstwa.

Wykrywa:
  1. Proby brute-force logowania SSH (auth.log)
  2. Skanowanie / rekonesans na serwerze WWW (access.log)
  3. Proby SQL Injection i XSS w zadaniach HTTP (access.log)

Uzycie:
  python3 log_analyzer.py --auth sample_logs/auth.log --access sample_logs/access.log
"""

import argparse
import re
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote


# ---------------------------------------------------------------------------
# KONFIGURACJA PROGOW WYKRYWANIA
# ---------------------------------------------------------------------------
# Ile nieudanych logowan z jednego IP uznajemy za brute force.
BRUTE_FORCE_THRESHOLD = 5

# Ile requestow 404 z jednego IP uznajemy za skanowanie (rekonesans).
SCAN_THRESHOLD = 4

# Wzorce charakterystyczne dla prob SQL Injection w URL / query string.
SQLI_PATTERNS = [
    r"'.*or.*'.*=.*'",      # ' OR '1'='1
    r"drop\s+table",         # DROP TABLE
    r"union\s+select",       # UNION SELECT
    r"--",                   # komentarz SQL uzywany do obciecia zapytania
    r";\s*--",
]

# Wzorce charakterystyczne dla prob XSS (Cross-Site Scripting).
XSS_PATTERNS = [
    r"<script.*?>",
    r"onerror\s*=",
    r"javascript:",
]

# Sciezki czesto skanowane przez atakujacych szukajacych podatnosci.
SUSPICIOUS_PATHS = [
    "admin", "wp-admin", "phpmyadmin", ".env", "config.php",
    "backup", ".git", "shell.php",
]


# ---------------------------------------------------------------------------
# CZESC 1 — ANALIZA auth.log (SSH brute force)
# ---------------------------------------------------------------------------

def parse_auth_log(path):
    """
    Czyta plik auth.log linia po linii i wyciaga zdarzenia logowania SSH.

    Zwraca liste slownikow, kazdy opisujacy jedno zdarzenie:
      {"status": "failed"/"accepted", "user": str, "ip": str, "raw": str}
    """
    # Przyklad linii ktora parsujemy:
    # May 10 14:32:01 serwer sshd[2001]: Failed password for root from 192.168.1.50 port 41001 ssh2
    pattern = re.compile(
        r"(?P<status>Failed|Accepted) (?:password|publickey) for "
        r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
    )

    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                events.append({
                    "status": match.group("status").lower(),
                    "user": match.group("user"),
                    "ip": match.group("ip"),
                    "raw": line.strip(),
                })
    return events


def detect_brute_force(events):
    """
    Grupuje nieudane logowania po IP i flaguje te, ktore przekroczyly prog.

    Zwraca liste alertow: [{"ip": str, "attempts": int, "users_tried": set}]
    """
    failed_by_ip = defaultdict(list)

    for event in events:
        if event["status"] == "failed":
            failed_by_ip[event["ip"]].append(event["user"])

    alerts = []
    for ip, users in failed_by_ip.items():
        if len(users) >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "ip": ip,
                "attempts": len(users),
                "users_tried": sorted(set(users)),
            })

    # Sortuj od najbardziej agresywnego ataku
    alerts.sort(key=lambda a: a["attempts"], reverse=True)
    return alerts


def check_successful_login_after_brute_force(events, brute_force_ips):
    """
    Najbardziej krytyczny sygnal: IP ktore najpierw brute-forcowalo,
    a POTEM zdobylo udane logowanie. To oznacza ze atak sie powiodl!
    """
    compromised = []
    for event in events:
        if event["status"] == "accepted" and event["ip"] in brute_force_ips:
            compromised.append(event)
    return compromised


# ---------------------------------------------------------------------------
# CZESC 2 — ANALIZA access.log (skanowanie, SQLi, XSS)
# ---------------------------------------------------------------------------

def parse_access_log(path):
    """
    Czyta plik access.log (format Apache Common/Combined Log Format).

    Przyklad linii:
    192.168.1.77 - - [10/May/2026:09:15:01 +0200] "GET /admin.php HTTP/1.1" 404 210

    Zwraca liste slownikow:
      {"ip": str, "request": str, "status_code": int}
    """
    pattern = re.compile(
        r'(?P<ip>[\d.]+) \S+ \S+ \[.*?\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" '
        r'(?P<status>\d+) \S+'
    )

    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                entries.append({
                    "ip": match.group("ip"),
                    "method": match.group("method"),
                    "path": match.group("path"),
                    "status_code": int(match.group("status")),
                })
    return entries


def detect_scanning(entries):
    """
    Wykrywa rekonesans: wiele requestow 404 z jednego IP w krotkim czasie,
    zwlaszcza do znanych, "podejrzanych" sciezek (np. /wp-admin, /.env).
    """
    not_found_by_ip = defaultdict(list)

    for entry in entries:
        if entry["status_code"] == 404:
            not_found_by_ip[entry["ip"]].append(entry["path"])

    alerts = []
    for ip, paths in not_found_by_ip.items():
        suspicious_hits = [
            p for p in paths
            if any(sus in p.lower() for sus in SUSPICIOUS_PATHS)
        ]
        if len(paths) >= SCAN_THRESHOLD:
            alerts.append({
                "ip": ip,
                "requests_404": len(paths),
                "suspicious_paths_hit": suspicious_hits,
            })

    alerts.sort(key=lambda a: a["requests_404"], reverse=True)
    return alerts


def detect_injection_attempts(entries):
    """
    Skanuje sciezki zadan HTTP pod katem wzorcow SQL Injection i XSS.

    WAZNE: przegladarki i narzedzia atakujace koduja znaki specjalne w URL
    (np. spacja -> %20, apostrof -> %27). Realny atak w logu wyglada np. tak:
        /login?user=admin%27--&pass=x
    a NIE tak:
        /login?user=admin'--&pass=x
    Dlatego zanim porownamy sciezke ze wzorcami ataku, musimy ja
    ZDEKODOWAC funkcja unquote() — inaczej regex nigdy nie znajdzie dopasowania.
    """
    alerts = []

    for entry in entries:
        path_decoded = unquote(entry["path"]).lower()

        for pattern in SQLI_PATTERNS:
            if re.search(pattern, path_decoded):
                alerts.append({
                    "ip": entry["ip"],
                    "type": "SQL Injection",
                    "path": entry["path"],          # oryginal do raportu
                    "decoded": path_decoded,          # zdekodowany, do wyjasnienia
                })
                break  # nie duplikuj alertu dla tej samej linii

        for pattern in XSS_PATTERNS:
            if re.search(pattern, path_decoded):
                alerts.append({
                    "ip": entry["ip"],
                    "type": "XSS",
                    "path": entry["path"],
                    "decoded": path_decoded,
                })
                break

    return alerts


# ---------------------------------------------------------------------------
# CZESC 3 — RAPORT KONCOWY
# ---------------------------------------------------------------------------

def print_section(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def generate_report(auth_path, access_path):
    """Glowna funkcja spinajaca cala analize i drukujaca raport SOC."""

    print("\n" + "#" * 70)
    print("#  SOC LOG ANALYZER — RAPORT BEZPIECZENSTWA")
    print(f"#  Wygenerowano: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("#" * 70)

    # --- SSH / auth.log ---
    print_section("1. ANALIZA LOGOWAN SSH (auth.log)")
    auth_events = parse_auth_log(auth_path)
    print(f"Przeanalizowano {len(auth_events)} zdarzen logowania.")

    brute_force_alerts = detect_brute_force(auth_events)

    if not brute_force_alerts:
        print("Brak wykrytych prob brute-force.")
    else:
        print(f"\n[!] WYKRYTO {len(brute_force_alerts)} PODEJRZANY(CH) ADRES(OW) IP:\n")
        for alert in brute_force_alerts:
            print(f"  IP: {alert['ip']}")
            print(f"    Liczba nieudanych prob: {alert['attempts']}")
            print(f"    Testowane konta: {', '.join(alert['users_tried'])}")

        # Sprawdz czy ktorys z atakujacych sie wlamal
        brute_force_ips = {a["ip"] for a in brute_force_alerts}
        compromised = check_successful_login_after_brute_force(auth_events, brute_force_ips)

        if compromised:
            print("\n  [KRYTYCZNE] UDANE LOGOWANIE PO SERII NIEUDANYCH PROB:")
            for event in compromised:
                print(f"    -> IP {event['ip']} zalogowal sie jako '{event['user']}'!")
                print(f"       To wyglada na SKUTECZNY atak brute-force.")

    # --- WWW / access.log ---
    print_section("2. ANALIZA RUCHU WWW (access.log)")
    access_entries = parse_access_log(access_path)
    print(f"Przeanalizowano {len(access_entries)} zadan HTTP.")

    scan_alerts = detect_scanning(access_entries)
    if scan_alerts:
        print(f"\n[!] WYKRYTO SKANOWANIE Z {len(scan_alerts)} ADRES(OW) IP:\n")
        for alert in scan_alerts:
            print(f"  IP: {alert['ip']} — {alert['requests_404']} zadan 404")
            if alert["suspicious_paths_hit"]:
                print(f"    Podejrzane sciezki: {', '.join(alert['suspicious_paths_hit'])}")
    else:
        print("Brak wykrytego skanowania.")

    injection_alerts = detect_injection_attempts(access_entries)
    if injection_alerts:
        print(f"\n[!] WYKRYTO {len(injection_alerts)} PROB(Y) INJEKCJI:\n")
        for alert in injection_alerts:
            print(f"  {alert['type']} z IP {alert['ip']}")
            print(f"    Zadanie: {alert['path']}")
    else:
        print("Brak wykrytych prob SQL Injection / XSS.")

    # --- Podsumowanie ---
    print_section("PODSUMOWANIE")
    total_alerts = len(brute_force_alerts) + len(scan_alerts) + len(injection_alerts)
    print(f"Lacznie wygenerowanych alertow: {total_alerts}")
    if total_alerts == 0:
        print("Status: BRAK ZAGROZEN")
    elif total_alerts <= 2:
        print("Status: NISKIE RYZYKO — rutynowa weryfikacja")
    else:
        print("Status: WYSOKIE RYZYKO — wymaga natychmiastowej reakcji zespolu SOC")
    print()


# ---------------------------------------------------------------------------
# PUNKT WEJSCIA
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SOC Log Analyzer — wykrywanie zagrozen w logach SSH i WWW."
    )
    parser.add_argument(
        "--auth", default="sample_logs/auth.log",
        help="Sciezka do pliku auth.log (domyslnie: sample_logs/auth.log)"
    )
    parser.add_argument(
        "--access", default="sample_logs/access.log",
        help="Sciezka do pliku access.log (domyslnie: sample_logs/access.log)"
    )
    args = parser.parse_args()

    generate_report(args.auth, args.access)
