"""Deduplicate the zeus pcap (USTC-TFC2016): drop the second copy of VM frames re-emitted by MAC 78:e4:00:6c:39:cd.

Background: every outbound frame of VMs .250/.251 appears twice in the pcap -- once with the VM's source MAC
(08:00:27:...) and once with source MAC 78:e4:00:6c:39:cd -- so Zeek counts orig_pkts (and UDP orig_bytes)
twice.

Dedup rule (conservative): a frame is DROPPED only if
  (1) its source MAC is 78:e4:00:6c:39:cd, AND
  (2) its content from the IP header onwards (byte 14 on) is byte-for-byte IDENTICAL to another frame
      already kept from a different source MAC, within <= MAX_GAP seconds.
78:e4 frames without an identical twin (e.g. 78:e4's own ARP) are KEPT. Only classic pcap (not pcapng)
is supported -- zeus.pcap is classic pcap.

Usage:
  python3 -I dedup_zeus_pcap.py <pcap_in> <pcap_out>        # write result + summary
  python3 -I dedup_zeus_pcap.py <pcap_in> --dry-run         # summary only
"""
import struct
import sys
from collections import Counter, OrderedDict

DUP_MAC = bytes.fromhex("78e4006c39cd")
MAX_GAP = 1.0  # seconds; observed twins are ~tens of microseconds apart


def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, nano = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, nano = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, nano = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, nano = ">", True
        else:
            raise ValueError(f"Not a classic pcap (magic {magic.hex()})")
        yield ("header", gh)
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            ts_sec, ts_frac, incl, orig = struct.unpack(endian + "IIII", rh)
            data = f.read(incl)
            ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
            yield ("pkt", (ts, rh, data))


def main():
    src = sys.argv[1]
    dry = len(sys.argv) > 2 and sys.argv[2] == "--dry-run"
    out = None if dry else open(sys.argv[2], "wb")

    recent = OrderedDict()  # ip_bytes -> (ts, src_mac) of kept frames
    stats = Counter()
    dropped_by_ip = Counter()
    kept_dup_mac_examples = []

    for kind, item in read_pcap(src):
        if kind == "header":
            if out:
                out.write(item)
            continue
        ts, rh, data = item
        stats["total"] += 1
        smac = data[6:12]
        ethertype = data[12:14]
        ip_bytes = data[14:]

        # drop entries older than the window
        while recent:
            k, (t0, _) = next(iter(recent.items()))
            if ts - t0 > MAX_GAP:
                recent.popitem(last=False)
            else:
                break

        drop = False
        if smac == DUP_MAC:
            stats["from_dup_mac"] += 1
            prev = recent.get(ip_bytes)
            if prev is not None and prev[1] != DUP_MAC:
                drop = True
            else:
                stats["dup_mac_without_twin"] += 1
                if len(kept_dup_mac_examples) < 5:
                    kept_dup_mac_examples.append((round(ts, 6), ethertype.hex(), len(data)))

        if drop:
            stats["dropped"] += 1
            if ethertype == b"\x08\x00" and len(data) >= 34:
                dropped_by_ip[".".join(str(b) for b in data[26:30])] += 1
            continue

        stats["kept"] += 1
        if ethertype in (b"\x08\x00", b"\x86\xdd"):
            recent[ip_bytes] = (ts, smac)
        if out:
            out.write(rh)
            out.write(data)

    if out:
        out.close()
    print("frames total            :", stats["total"])
    print("frames from MAC 78:e4   :", stats["from_dup_mac"])
    print("  dropped (identical IP twin from another MAC):", stats["dropped"])
    print("  kept (no twin):", stats["dup_mac_without_twin"], "examples (ts, ethertype, len):", kept_dup_mac_examples)
    print("frames kept             :", stats["kept"])
    print("dropped per source IP   :", dict(dropped_by_ip.most_common(6)))


if __name__ == "__main__":
    main()
