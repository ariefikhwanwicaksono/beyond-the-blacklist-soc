"""Show the plaintext C2 protocol of the two VMs in the USTC-TFC2016 "Zeus" capture (192.168.0.250/.251).

Paper claim: the dominant C2 is NOT Zeus but an x0Proto RAT (likely Blackshades or a derivative): fields are
separated by 0x0C (cmd|len|payload); "x0" = registration, "x74" = ipinfodb geolocation key (client answers with a
country), "x49" = download command (HBX321e23e23r.exe), "x34" = visit URL, "x53" = ping / active-window title.
The C2 domain zxczxczxc.zapto.org (FBI Blackshades domain list) resolves to 184.82.139.38, TCP ports 3080/3178.
Compare with ET Open "ET MALWARE x0Proto" rules (sid 2012236-2012240) and sid 2014101.

Reads classic pcap only (zeus.pcap / zeus_dedup.pcap are classic pcap); no third-party packages.
Usage: python3 inspect_zeus_x0proto.py <zeus_dedup.pcap> [max_payloads]
"""
import re
import struct
import sys
from collections import Counter

C2_IP = bytes([184, 82, 139, 38])
C2_PORTS = {3080, 3178}
DUP_MAC = bytes.fromhex("78e4006c39cd")  # bridge re-emitting VM frames (see tools/dedup_zeus_pcap.py)


def tcp_payloads(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        endian = "<" if gh[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            ts_sec, ts_frac, incl, _ = struct.unpack(endian + "IIII", rh)
            d = f.read(incl)
            if d[6:12] == DUP_MAC or d[12:14] != b"\x08\x00" or d[23] != 6:
                continue
            ihl = (d[14] & 0x0F) * 4
            src, dst = d[26:30], d[30:34]
            t = 14 + ihl
            sport, dport = struct.unpack(">HH", d[t:t + 4])
            doff = (d[t + 12] >> 4) * 4
            payload = d[t + doff:]
            if payload and C2_IP in (src, dst) and (sport in C2_PORTS or dport in C2_PORTS):
                who = "server" if src == C2_IP else ".".join(map(str, src))
                yield ts_sec, who, payload


def main():
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    cmds = Counter()
    shown = 0
    for ts, who, p in tcp_payloads(sys.argv[1]):
        text = p.decode("latin-1")
        for m in re.finditer(r"x(\d{1,2})\x0c", text):
            cmds[(who if who == "server" else "client", "x" + m.group(1))] += 1
        if shown < limit and "\x0c" in text:
            print(f"{ts} {who:>14}: " + re.sub(r"[^\x20-\x7e\x0c]", ".", text).replace("\x0c", "|")[:200])
            shown += 1
    print("\ncommand counts (sender, command):")
    for (who, c), n in sorted(cmds.items()):
        print(f"  {who:6s} {c:4s} {n}")


if __name__ == "__main__":
    main()
