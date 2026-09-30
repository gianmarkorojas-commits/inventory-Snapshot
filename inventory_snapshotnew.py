#!/usr/bin/env python3
"""
Inventory snapshot: records which devices (IP/MAC pairs) this machine's
ARP/neighbor cache currently knows about, with a timestamp, and reports what
changed since the last snapshot.

IMPORTANT CAVEAT — this is NOT the access point's own client table:
it's the ARP/neighbor cache of the machine running this script. That means:
  - It only shows devices this machine has actually exchanged L2 traffic
    with recently. A device that's alive but hasn't spoken to this host
    won't appear, even though the AP knows about it.
  - Entries age out on their own (Linux marks them STALE after a couple
    minutes of inactivity and drops them after longer), independent of
    whether the device is still on the network. A "gone" device in the
    diff may just mean "hasn't talked to this host lately," not "left."
  - It only sees the broadcast domain/VLAN this host is on.
Treat "gone" as "not seen from here recently," not "confirmed absent."
Run it often enough (e.g. hourly via cron, not just once a day) if you
want the gaps between snapshots to be short enough to trust.

Usage:
    python3 inventory_snapshot.py snapshot              # take + append + diff vs previous
    python3 inventory_snapshot.py snapshot --log PATH    # use a specific log file
    python3 inventory_snapshot.py diff                   # re-show diff of last two snapshots
    python3 inventory_snapshot.py history                # list all snapshots taken so far
"""

import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LOG = Path("inventory_snapshots.jsonl")

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.IGNORECASE)


def _normalize_mac(mac):
    mac = mac.strip().lower().replace("-", ":")
    return mac if MAC_RE.match(mac) else None


def _read_linux_ip_neigh():
    out = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, check=True).stdout
    devices = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        state = parts[-1]
        iface = None
        mac = None
        if "dev" in parts:
            iface = parts[parts.index("dev") + 1]
        if "lladdr" in parts:
            mac = _normalize_mac(parts[parts.index("lladdr") + 1])
        if state.upper() in ("FAILED", "INCOMPLETE"):
            continue
        if not mac:
            continue
        devices.append({"ip": ip, "mac": mac, "iface": iface, "state": state.upper()})
    return devices


def _read_proc_net_arp():
    devices = []
    try:
        with open("/proc/net/arp") as f:
            lines = f.readlines()[1:]
    except FileNotFoundError:
        return devices
    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, _hwtype, flags, mac, _mask, iface = parts[:6]
        if flags == "0x0":  # incomplete
            continue
        mac = _normalize_mac(mac)
        if not mac:
            continue
        devices.append({"ip": ip, "mac": mac, "iface": iface, "state": "REACHABLE"})
    return devices


def _read_arp_a():
    """Portable fallback: parse `arp -a` output (macOS/BSD/Windows/Linux)."""
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=True).stdout
    devices = []
    # Matches both "host (192.168.1.5) at aa:bb:cc:dd:ee:ff on en0 ..." (BSD/macOS)
    # and "  192.168.1.5          aa-bb-cc-dd-ee-ff     dynamic" (Windows)
    # and "? (192.168.1.5) at aa:bb:cc:dd:ee:ff [ether] on wlan0" (Linux net-tools)
    pattern = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3}).*?"
        r"((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"
    )
    for line in out.splitlines():
        if "incomplete" in line.lower():
            continue
        m = pattern.search(line)
        if not m:
            continue
        ip, mac = m.group(1), m.group(2)
        mac = _normalize_mac(mac)
        if not mac:
            continue
        iface_m = re.search(r"on (\S+)|Iface[: ]+(\S+)", line)
        iface = next((g for g in (iface_m.groups() if iface_m else []) if g), None)
        devices.append({"ip": ip, "mac": mac, "iface": iface, "state": "REACHABLE"})
    return devices


def _is_ipv4(ip_str):
    try:
        return ipaddress.ip_address(ip_str).version == 4
    except ValueError:
        return False


def get_devices(include_ipv6=False):
    """Best available neighbor table for this platform, as a list of
    {ip, mac, iface, state} dicts (MAC-bearing, non-incomplete entries only).

    IPv4-only by default: a MAC routinely carries several simultaneous IPv6
    addresses (link-local, global, and privacy-extension addresses that
    rotate on their own), which has nothing to do with whether a device's
    network address is a stable identifier and would otherwise swamp real
    changes with routine IPv6 churn.
    """
    if sys.platform.startswith("linux") and shutil.which("ip"):
        try:
            devices = _read_linux_ip_neigh()
        except (subprocess.CalledProcessError, FileNotFoundError):
            devices = None
    else:
        devices = None
    if devices is None and sys.platform.startswith("linux"):
        devices = _read_proc_net_arp() or None
    if devices is None and shutil.which("arp"):
        devices = _read_arp_a()
    if devices is None:
        sys.exit("error: no way to read the ARP/neighbor table on this platform "
                  "(need `ip`, /proc/net/arp, or `arp` on PATH)")
    if not include_ipv6:
        devices = [d for d in devices if _is_ipv4(d["ip"])]
    return devices


def take_snapshot(include_ipv6=False):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "devices": get_devices(include_ipv6=include_ipv6),
    }


def load_snapshots(log_path):
    if not log_path.exists():
        return []
    snapshots = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                snapshots.append(json.loads(line))
    return snapshots


def append_snapshot(log_path, snapshot):
    with open(log_path, "a") as f:
        f.write(json.dumps(snapshot) + "\n")


def diff_snapshots(prev, curr):
    """
    Returns a dict describing what changed between two snapshots, keyed on
    MAC address as the device identity (the question this whole exercise is
    about: is IP-as-identity safe, or does it drift under a stable MAC?).

    A MAC can legitimately hold more than one simultaneous IP, so each MAC
    maps to a *set* of IPs rather than a single one.
    """
    prev_by_mac, curr_by_mac = {}, {}
    for d in prev["devices"]:
        prev_by_mac.setdefault(d["mac"], set()).add(d["ip"])
    for d in curr["devices"]:
        curr_by_mac.setdefault(d["mac"], set()).add(d["ip"])

    prev_by_ip = {d["ip"]: d["mac"] for d in prev["devices"]}
    curr_by_ip = {d["ip"]: d["mac"] for d in curr["devices"]}

    new_macs = sorted(curr_by_mac.keys() - prev_by_mac.keys())
    gone_macs = sorted(prev_by_mac.keys() - curr_by_mac.keys())
    common_macs = curr_by_mac.keys() & prev_by_mac.keys()

    mac_ip_changed = sorted(
        (mac, sorted(prev_by_mac[mac] - curr_by_mac[mac]), sorted(curr_by_mac[mac] - prev_by_mac[mac]))
        for mac in common_macs if prev_by_mac[mac] != curr_by_mac[mac]
    )
    stable_macs = sorted(mac for mac in common_macs if prev_by_mac[mac] == curr_by_mac[mac])

    ip_mac_changed = sorted(
        (ip, prev_by_ip[ip], curr_by_ip[ip])
        for ip in (curr_by_ip.keys() & prev_by_ip.keys())
        if prev_by_ip[ip] != curr_by_ip[ip]
    )

    return {
        "new_macs": [(mac, sorted(curr_by_mac[mac])) for mac in new_macs],
        "gone_macs": [(mac, sorted(prev_by_mac[mac])) for mac in gone_macs],
        "mac_ip_changed": mac_ip_changed,
        "ip_mac_changed": ip_mac_changed,
        "stable_macs": stable_macs,
    }


def print_diff(prev, curr, d):
    span = f"{prev['timestamp']} -> {curr['timestamp']}"
    print(f"\nDiff over {span}")
    print(f"  stable (same MAC, same IP(s)): {len(d['stable_macs'])}")

    if d["new_macs"]:
        print(f"\n  new devices ({len(d['new_macs'])}):")
        for mac, ips in d["new_macs"]:
            print(f"    + {mac}  now at {', '.join(ips)}")

    if d["gone_macs"]:
        print(f"\n  devices not seen this time ({len(d['gone_macs'])}):")
        for mac, ips in d["gone_macs"]:
            print(f"    - {mac}  was at {', '.join(ips)}")

    if d["mac_ip_changed"]:
        print(f"\n  ADDRESS CHANGED for known device ({len(d['mac_ip_changed'])}):")
        for mac, removed, added in d["mac_ip_changed"]:
            print(f"    ~ {mac}  -{', '.join(removed) or '(none)'}  +{', '.join(added) or '(none)'}")

    if d["ip_mac_changed"]:
        print(f"\n  same IP, different device now ({len(d['ip_mac_changed'])}):")
        for ip, old_mac, new_mac in d["ip_mac_changed"]:
            print(f"    ~ {ip}  {old_mac} -> {new_mac}")

    if not any([d["new_macs"], d["gone_macs"], d["mac_ip_changed"], d["ip_mac_changed"]]):
        print("\n  no changes.")


def cmd_snapshot(args):
    log_path = Path(args.log)
    previous = load_snapshots(log_path)
    snap = take_snapshot(include_ipv6=args.include_ipv6)
    append_snapshot(log_path, snap)
    print(f"Recorded snapshot at {snap['timestamp']}: {len(snap['devices'])} device(s) "
          f"-> {log_path}")
    for dev in sorted(snap["devices"], key=lambda d: d["ip"]):
        print(f"  {dev['ip']:<20} {dev['mac']:<18} {dev.get('iface') or '-':<12} {dev['state']}")
    if previous:
        d = diff_snapshots(previous[-1], snap)
        print_diff(previous[-1], snap, d)
    else:
        print("\n(no previous snapshot to diff against — this is the first one)")


def cmd_diff(args):
    log_path = Path(args.log)
    snapshots = load_snapshots(log_path)
    if len(snapshots) < 2:
        sys.exit(f"error: need at least 2 snapshots in {log_path} to diff, found {len(snapshots)}")
    d = diff_snapshots(snapshots[-2], snapshots[-1])
    print_diff(snapshots[-2], snapshots[-1], d)


def cmd_history(args):
    log_path = Path(args.log)
    snapshots = load_snapshots(log_path)
    if not snapshots:
        print(f"no snapshots recorded yet in {log_path}")
        return
    for snap in snapshots:
        print(f"{snap['timestamp']}  {len(snap['devices'])} device(s)")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                         help=f"snapshot log file (default: {DEFAULT_LOG})")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_snap = sub.add_parser("snapshot", help="take a snapshot, append it, diff vs previous")
    p_snap.add_argument("--include-ipv6", action="store_true",
                         help="also record IPv6 neighbors (noisy: privacy-extension "
                              "addresses rotate on their own and will look like churn)")
    p_snap.set_defaults(func=cmd_snapshot)

    sub.add_parser("diff", help="show diff between the two most recent snapshots").set_defaults(func=cmd_diff)
    sub.add_parser("history", help="list all recorded snapshots").set_defaults(func=cmd_history)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
