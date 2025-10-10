#!/usr/bin/env python3
"""
ip_geo.py
Resolver hostname -> IP(s) -> geolocation lookup (with basic error handling).
Requires: requests
Usage:
    python ip_geo.py example.com
"""

import socket
import requests
import argparse
import json
import sys
from ipaddress import ip_address, IPv4Address, IPv6Address, IPv4Network


DEFAULT_TIMEOUT = 6  
GEO_API_PRIMARY = "https://ipapi.co/{ip}/json/"      
GEO_API_FALLBACK = "https://geolocation-db.com/jsonp/{ip}"  

PRIVATE_NETWORKS = [
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("127.0.0.0/8"),   
    IPv4Network("169.254.0.0/16")
]

# --- Helpers ---
def is_private_ipv4(addr_str):
    try:
        ip = ip_address(addr_str)
        if isinstance(ip, IPv4Address):
            for net in PRIVATE_NETWORKS:
                if ip in net:
                    return True
        return False
    except Exception:
        return False

def resolve_hostname(hostname):
    """Return list of unique IPs for a hostname (IPv4 and IPv6 if available)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except socket.gaierror as e:
        raise RuntimeError(f"DNS resolution failed for '{hostname}': {e}")

def get_geo_ip_ipapi(ip):
    """Primary lookup using ipapi.co"""
    url = GEO_API_PRIMARY.format(ip=ip)
    try:
        resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        # propagate to allow fallback
        raise

def get_geo_ip_geolocationdb(ip):
    """Fallback: geolocation-db returns JSONP, so strip wrapper."""
    url = GEO_API_FALLBACK.format(ip=ip)
    resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
    resp.raise_for_status()
    text = resp.text.strip()
    # geolocation-db returns e.g. callback({...})
    if text.startswith("{"):
        return resp.json()
    # try to strip JSONP wrapper
    try:
        start = text.index("(") + 1
        end = text.rindex(")")
        payload = text[start:end]
        return json.loads(payload)
    except Exception:
        # last resort: try to parse raw as json
        return resp.json()

def pretty_print_geo(ip, geo):
    print("\n---", ip, "---")
    if not geo:
        print("No geolocation data.")
        return
    # Print fields that commonly exist in different providers
    fields = [
        ("ip", "ip"),
        ("city", "city"),
        ("region", "region"),
        ("region_name", "region_name"),
        ("country", "country"),
        ("country_name", "country_name"),
        ("country_code", "country_code"),
        ("postal", "postal"),
        ("latitude", "latitude"),
        ("longitude", "longitude"),
        ("org", "org"),
        ("isp", "isp"),
        ("timezone", "timezone"),
        ("asn", "asn")
    ]
    for key_alias in fields:
        # key_alias might be a tuple where either element may exist in response
        if isinstance(key_alias, tuple):
            found = False
            for key in key_alias:
                if key in geo and geo[key] not in (None, ""):
                    print(f"{key:12}: {geo[key]}")
                    found = True
                    break
            if not found:
                # don't print missing field
                pass
        else:
            if key_alias in geo:
                print(f"{key_alias:12}: {geo.get(key_alias)}")

    # print remaining keys if any
    extra = {k: v for k, v in geo.items() if k not in sum([list(k if isinstance(k, tuple) else [k]) for k in fields], [])}
    if extra:
        print("\nOther data:")
        for k, v in extra.items():
            print(f"{k:12}: {v}")

# --- Main flow ---
def main():
    parser = argparse.ArgumentParser(description="Resolve hostname to IP(s) and lookup geolocation")
    parser.add_argument("hostname", help="domain or hostname to lookup")
    args = parser.parse_args()

    hostname = args.hostname.strip()
    if hostname == "":
        print("Hostname kosong.", file=sys.stderr)
        sys.exit(1)

    try:
        ips = resolve_hostname(hostname)
    except RuntimeError as e:
        print(e, file=sys.stderr)
        sys.exit(2)

    print(f"Resolved {hostname} -> {len(ips)} IP(s): {', '.join(ips)}")

    for ip in ips:
        if is_private_ipv4(ip):
            print(f"\n--- {ip} ---")
            print("Alamat IP bersifat privat/loopback/link-local. Tidak ada data geolokasi publik.")
            continue

        geo = None
        # try primary
        try:
            geo = get_geo_ip_ipapi(ip)
        except Exception as e_primary:
            # try fallback
            try:
                geo = get_geo_ip_geolocationdb(ip)
            except Exception as e_fb:
                print(f"\n--- {ip} ---")
                print("Gagal mengambil data geolokasi dari API.")
                print("Primary error:", str(e_primary))
                print("Fallback error:", str(e_fb))
                continue

        pretty_print_geo(ip, geo)

if __name__ == "__main__":
    main()
