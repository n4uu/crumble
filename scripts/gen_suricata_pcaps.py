#!/usr/bin/env python3
"""Write the synthetic captures the Suricata rules are tested against.

Everything is made up: RFC 5737 addresses, example host names, a fake
MachineGuid. The positive capture speaks the raw TCP backdoor protocol as
reconstructed by crumble; the negative one has the same JSON in places the
rule must ignore (an HTTP body, another app, an inbound connection).

    python3 scripts/gen_suricata_pcaps.py pos.pcap neg.pcap
"""
import struct, sys, time

def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def ip4(a): return bytes(int(x) for x in a.split("."))

def pkt(src, dst, sp, dp, seq, ack, flags, data=b""):
    tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0) + data
    ph = ip4(src) + ip4(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(ph + tcp)) + tcp[18:]
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, ip4(src), ip4(dst))
    iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + iph + tcp

def session(c, s, cp, sp, turns):
    out, cs, ss = [], 1000, 5000
    out.append(pkt(c, s, cp, sp, cs, 0, 0x02)); cs += 1
    out.append(pkt(s, c, sp, cp, ss, cs, 0x12)); ss += 1
    out.append(pkt(c, s, cp, sp, cs, ss, 0x10))
    for who, data in turns:
        if who == "c":
            out.append(pkt(c, s, cp, sp, cs, ss, 0x18, data)); cs += len(data)
            out.append(pkt(s, c, sp, cp, ss, cs, 0x10))
        else:
            out.append(pkt(s, c, sp, cp, ss, cs, 0x18, data)); ss += len(data)
            out.append(pkt(c, s, cp, sp, cs, ss, 0x10))
    out.append(pkt(c, s, cp, sp, cs, ss, 0x11)); cs += 1
    out.append(pkt(s, c, sp, cp, ss, cs, 0x11)); ss += 1
    out.append(pkt(c, s, cp, sp, cs, ss, 0x10))
    return out

def write(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        t = 1793635200
        for i, p in enumerate(packets):
            f.write(struct.pack("<IIII", t + i, 0, len(p), len(p)) + p)

ts = '"timestamp":"2026-11-02T16:42:21.024Z"}\n'
pos = session("192.0.2.10", "198.51.100.20", 49712, 15152, [
    ("c", ('{"status":"connected","message":"win32?4c4c4544-0042-3510-8051-b4c04f4e3832?DESKTOP-EXAMPLE?0",' + ts).encode()),
    ("c", ('{"status":"keepalive","message":"",' + ts).encode()),
    ("s", b"whoami\n"),
    ("c", ('{"status":"completed","message":"Output: desktop-example\\\\dev\\r\\n",' + ts).encode()),
]) + session("192.0.2.11", "203.0.113.30", 50111, 443, [
    ("c", ('{"status":"connected","message":"darwin?A1B2C3D4-0000-1111-2222-333344445555?dev-mbp.local?1",' + ts).encode()),
])
neg = session("192.0.2.12", "203.0.113.31", 50200, 80, [
    ("c", b'POST /api/status HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 70\r\n\r\n{"status":"connected","message":"win32?a?b?0","timestamp":"2026-11-02"}'),
    ("s", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
]) + session("192.0.2.13", "203.0.113.32", 50300, 9000, [
    ("c", ('{"status":"connected","message":"worker ready",' + ts).encode()),
    ("c", ('{"status":"ok","message":"",' + ts).encode()),
]) + session("203.0.113.33", "192.0.2.14", 40000, 15152, [
    ("c", ('{"status":"connected","message":"linux?abc?host?0",' + ts).encode()),
])
write(sys.argv[1], pos); write(sys.argv[2], neg)
print(len(pos), len(neg))
