#!/usr/bin/env python3
"""
continuous_generator.py
=======================

Continuously generates 15,000-packet PCAP files representing a realistic mix
of CIC-IDS-2017-style traffic. A new file is written every `interval`
seconds, so a downstream tcpreplay loop always has fresh packets.

Each generated PCAP contains roughly:
  * 60% benign traffic: HTTP, DNS, SSH sessions, ICMP echoes
  * 15% DDoS SYN flood from spoofed sources
  * 10% port scanning bursts
  * 8%  SSH brute force attempts
  * 5%  web brute force POST flood against /login
  * 2%  noise (random connections)

The exact mix varies per file using a small randomisation, so the
demonstration looks alive rather than showing the same canned pattern.

Output:
  /pcaps/live.pcap            most recent 15k-packet capture
  /pcaps/live.pcap.tmp        intermediate file during write
  /pcaps/stats.txt            current generation statistics

Usage:
  python continuous_generator.py [--interval SECONDS] [--packets N]

Default: 15,000 packets every 60 seconds.
"""

from __future__ import annotations

import argparse
import os
import random
import struct
import sys
import time
from pathlib import Path
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Pure-binary packet construction (same approach as the batch generator,
# kept here to avoid scapy dependency issues in containers)
# ---------------------------------------------------------------------------
def _ip_to_bytes(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ip_header(src: str, dst: str, proto: int, payload_len: int,
               ttl: int = 64, ident: int = 0) -> bytes:
    version_ihl = 0x45
    total_len = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH4s4s",
                      version_ihl, 0, total_len, ident, 0,
                      ttl, proto, 0,
                      _ip_to_bytes(src), _ip_to_bytes(dst))
    chk = _checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s",
                       version_ihl, 0, total_len, ident, 0,
                       ttl, proto, chk,
                       _ip_to_bytes(src), _ip_to_bytes(dst))


def _tcp_header(src_ip: str, dst_ip: str, sport: int, dport: int,
                seq: int, ack: int, flags: int, window: int = 65535,
                payload: bytes = b"") -> bytes:
    data_offset = (5 << 4)
    hdr = struct.pack("!HHIIBBHHH",
                      sport, dport, seq, ack,
                      data_offset, flags, window, 0, 0)
    pseudo = (_ip_to_bytes(src_ip) + _ip_to_bytes(dst_ip) +
              struct.pack("!BBH", 0, 6, len(hdr) + len(payload)))
    chk = _checksum(pseudo + hdr + payload)
    return struct.pack("!HHIIBBHHH",
                       sport, dport, seq, ack,
                       data_offset, flags, window, chk, 0)


def _udp_header(src_ip: str, dst_ip: str, sport: int, dport: int,
                payload: bytes) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = (_ip_to_bytes(src_ip) + _ip_to_bytes(dst_ip) +
              struct.pack("!BBH", 0, 17, length))
    chk = _checksum(pseudo + hdr + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, chk)


def _icmp_header(itype: int, code: int, ident: int, seq: int,
                 payload: bytes) -> bytes:
    hdr = struct.pack("!BBHHH", itype, code, 0, ident, seq)
    chk = _checksum(hdr + payload)
    return struct.pack("!BBHHH", itype, code, chk, ident, seq)


def _eth_header(ethertype: int = 0x0800) -> bytes:
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack("!H", ethertype)


def make_tcp(src_ip, dst_ip, sport, dport, flags, seq=0, ack=0, payload=b""):
    flag_map = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08,
                "A": 0x10, "U": 0x20}
    f = sum(flag_map.get(c, 0) for c in flags)
    tcp = _tcp_header(src_ip, dst_ip, sport, dport, seq, ack, f, 65535, payload)
    ip = _ip_header(src_ip, dst_ip, 6, len(tcp) + len(payload),
                    ident=random.randint(1, 65535))
    return _eth_header() + ip + tcp + payload


def make_udp(src_ip, dst_ip, sport, dport, payload):
    udp = _udp_header(src_ip, dst_ip, sport, dport, payload)
    ip = _ip_header(src_ip, dst_ip, 17, len(udp) + len(payload),
                    ident=random.randint(1, 65535))
    return _eth_header() + ip + udp + payload


def make_icmp(src_ip, dst_ip, itype=8, payload=b"abcdefghijklmnop"):
    icmp = _icmp_header(itype, 0, 0x1234, 1, payload)
    ip = _ip_header(src_ip, dst_ip, 1, len(icmp) + len(payload),
                    ident=random.randint(1, 65535))
    return _eth_header() + ip + icmp + payload


# ---------------------------------------------------------------------------
# PCAP file writer
# ---------------------------------------------------------------------------
PCAP_MAGIC = 0xA1B2C3D4


def write_pcap(path: Path, packets: List[Tuple[float, bytes]]) -> None:
    with path.open("wb") as fh:
        fh.write(struct.pack("!IHHiIII",
                             PCAP_MAGIC, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            fh.write(struct.pack("!IIII", sec, usec, len(data), len(data)))
            fh.write(data)


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------
INTERNAL = "192.168.10."
WEB_SERVER = "192.168.10.50"
DB_SERVER = "192.168.10.51"
DNS_SERVER = "192.168.10.10"
GATEWAY = "192.168.10.1"
CLIENTS = [f"{INTERNAL}{i}" for i in range(20, 40)]


class Clock:
    def __init__(self, start: float):
        self.t = start

    def tick(self, dt: float = 0.001) -> float:
        self.t += dt
        return self.t


# ---------------------------------------------------------------------------
# Traffic generators
# ---------------------------------------------------------------------------
def gen_http(clk, n_sessions: int) -> List[Tuple[float, bytes]]:
    """Benign HTTP request and response pairs."""
    out = []
    for _ in range(n_sessions):
        client = random.choice(CLIENTS)
        server = random.choice([WEB_SERVER, "8.8.8.8", "1.1.1.1", "104.18.32.7"])
        sport = random.randint(40000, 60000)
        seq_c = random.randint(1000, 9999999)
        seq_s = random.randint(1000, 9999999)

        out.append((clk.tick(0.001), make_tcp(client, server, sport, 80, "S", seq_c)))
        out.append((clk.tick(0.001), make_tcp(server, client, 80, sport, "SA", seq_s, seq_c+1)))
        out.append((clk.tick(0.001), make_tcp(client, server, sport, 80, "A", seq_c+1, seq_s+1)))

        req = (b"GET / HTTP/1.1\r\nHost: example.com\r\n"
               b"User-Agent: Mozilla/5.0\r\n\r\n")
        out.append((clk.tick(0.005), make_tcp(client, server, sport, 80, "PA",
                                              seq_c+1, seq_s+1, req)))

        body = b"<html><body>Welcome</body></html>"
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: " + str(len(body)).encode() +
                b"\r\n\r\n" + body)
        out.append((clk.tick(0.020), make_tcp(server, client, 80, sport, "PA",
                                              seq_s+1, seq_c+1+len(req), resp)))

        out.append((clk.tick(0.005), make_tcp(client, server, sport, 80, "FA",
                                              seq_c+1+len(req), seq_s+1+len(resp))))
        out.append((clk.tick(0.001), make_tcp(server, client, 80, sport, "FA",
                                              seq_s+1+len(resp), seq_c+2+len(req))))
    return out


def gen_dns(clk, n: int) -> List[Tuple[float, bytes]]:
    """DNS queries and responses."""
    out = []
    domains = ["example.com", "google.com", "ubuntu.com", "github.com",
               "wikipedia.org", "cloudflare.com", "stackoverflow.com"]
    for _ in range(n):
        client = random.choice(CLIENTS)
        domain = random.choice(domains)
        txid = random.randint(1, 65535)
        sport = random.randint(30000, 60000)

        qname = b""
        for label in domain.split("."):
            qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"
        question = qname + struct.pack("!HH", 1, 1)
        query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
        out.append((clk.tick(0.001), make_udp(client, DNS_SERVER, sport, 53, query)))

        answer = qname + struct.pack("!HHIH", 1, 1, 60, 4) + _ip_to_bytes("93.184.216.34")
        resp = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer
        out.append((clk.tick(0.005), make_udp(DNS_SERVER, client, 53, sport, resp)))
    return out


def gen_ssh(clk, n_sessions: int) -> List[Tuple[float, bytes]]:
    """Benign SSH sessions."""
    out = []
    for _ in range(n_sessions):
        client = random.choice(CLIENTS)
        sport = random.randint(40000, 60000)
        seq_c = random.randint(1000, 9999999)
        seq_s = random.randint(1000, 9999999)

        out.append((clk.tick(0.001), make_tcp(client, DB_SERVER, sport, 22, "S", seq_c)))
        out.append((clk.tick(0.001), make_tcp(DB_SERVER, client, 22, sport, "SA", seq_s, seq_c+1)))
        out.append((clk.tick(0.001), make_tcp(client, DB_SERVER, sport, 22, "A", seq_c+1, seq_s+1)))

        banner = b"SSH-2.0-OpenSSH_8.9p1\r\n"
        out.append((clk.tick(0.020), make_tcp(DB_SERVER, client, 22, sport, "PA",
                                              seq_s+1, seq_c+1, banner)))
        payload = bytes(random.randint(0, 255) for _ in range(random.randint(50, 200)))
        out.append((clk.tick(0.030), make_tcp(client, DB_SERVER, sport, 22, "PA",
                                              seq_c+1, seq_s+1+len(banner), payload)))
        out.append((clk.tick(0.010), make_tcp(client, DB_SERVER, sport, 22, "FA",
                                              seq_c+1+len(payload), seq_s+1+len(banner))))
    return out


def gen_icmp(clk, n_pairs: int) -> List[Tuple[float, bytes]]:
    out = []
    for _ in range(n_pairs):
        client = random.choice(CLIENTS)
        target = random.choice([GATEWAY, "8.8.8.8"])
        out.append((clk.tick(0.5), make_icmp(client, target, itype=8)))
        out.append((clk.tick(0.001), make_icmp(target, client, itype=0)))
    return out


def gen_ddos(clk, n_packets: int) -> List[Tuple[float, bytes]]:
    out = []
    sources = [f"172.16.{a}.{b}"
               for a in range(1, 8)
               for b in random.sample(range(2, 254), 30)]
    for _ in range(n_packets):
        src = random.choice(sources)
        sport = random.randint(1024, 65535)
        out.append((clk.tick(0.0003),
                    make_tcp(src, WEB_SERVER, sport, 80, "S",
                             seq=random.randint(1, 999999))))
    return out


def gen_portscan(clk, n_ports: int) -> List[Tuple[float, bytes]]:
    out = []
    attacker = f"172.16.0.{random.randint(5, 25)}"
    sport_base = random.randint(40000, 50000)
    ports = random.sample(range(1, 1024), min(n_ports, 1023))
    for i, p in enumerate(ports):
        out.append((clk.tick(0.001),
                    make_tcp(attacker, WEB_SERVER,
                             sport_base + (i % 1000), p, "S",
                             seq=random.randint(1, 999999))))
        if random.random() < 0.4:
            out.append((clk.tick(0.001),
                        make_tcp(WEB_SERVER, attacker, p,
                                 sport_base + (i % 1000), "RA")))
    return out


def gen_ssh_brute(clk, n_attempts: int) -> List[Tuple[float, bytes]]:
    out = []
    attacker = f"172.16.0.{random.randint(5, 25)}"
    for _ in range(n_attempts):
        sport = random.randint(40000, 60000)
        seq_c = random.randint(1000, 9999999)
        seq_s = random.randint(1000, 9999999)
        out.append((clk.tick(0.05), make_tcp(attacker, DB_SERVER, sport, 22, "S", seq_c)))
        out.append((clk.tick(0.005), make_tcp(DB_SERVER, attacker, 22, sport, "SA", seq_s, seq_c+1)))
        out.append((clk.tick(0.002), make_tcp(attacker, DB_SERVER, sport, 22, "A", seq_c+1, seq_s+1)))
        banner = b"SSH-2.0-OpenSSH_8.9p1\r\n"
        out.append((clk.tick(0.010), make_tcp(DB_SERVER, attacker, 22, sport, "PA",
                                              seq_s+1, seq_c+1, banner)))
        out.append((clk.tick(0.020), make_tcp(DB_SERVER, attacker, 22, sport, "FA",
                                              seq_s+1+len(banner), seq_c+1)))
    return out


def gen_web_brute(clk, n_attempts: int) -> List[Tuple[float, bytes]]:
    out = []
    attacker = f"172.16.0.{random.randint(5, 25)}"
    for i in range(n_attempts):
        sport = random.randint(40000, 60000)
        seq_c = random.randint(1000, 9999999)
        seq_s = random.randint(1000, 9999999)

        out.append((clk.tick(0.001), make_tcp(attacker, WEB_SERVER, sport, 80, "S", seq_c)))
        out.append((clk.tick(0.001), make_tcp(WEB_SERVER, attacker, 80, sport, "SA", seq_s, seq_c+1)))
        out.append((clk.tick(0.001), make_tcp(attacker, WEB_SERVER, sport, 80, "A", seq_c+1, seq_s+1)))

        body = f"username=admin&password=guess{i}".encode()
        req = (b"POST /login HTTP/1.1\r\n"
               b"Host: target.local\r\n"
               b"Content-Type: application/x-www-form-urlencoded\r\n"
               b"Content-Length: " + str(len(body)).encode() +
               b"\r\n\r\n" + body)
        out.append((clk.tick(0.020), make_tcp(attacker, WEB_SERVER, sport, 80, "PA",
                                              seq_c+1, seq_s+1, req)))
        resp = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
        out.append((clk.tick(0.030), make_tcp(WEB_SERVER, attacker, 80, sport, "PA",
                                              seq_s+1, seq_c+1+len(req), resp)))
    return out


# ---------------------------------------------------------------------------
# Compose a 15,000-packet capture with randomised mix
# ---------------------------------------------------------------------------
def build_capture(target_packets: int, epoch: float) -> List[Tuple[float, bytes]]:
    """Build one capture file with the configured packet count."""
    clk = Clock(start=epoch)
    out: List[Tuple[float, bytes]] = []

    # Calculate phase sizes proportionally to target
    # benign 60%, ddos 15%, portscan 10%, ssh-brute 8%, web-brute 5%, noise 2%
    benign_target = int(target_packets * 0.60)
    ddos_target = int(target_packets * 0.15)
    portscan_target = int(target_packets * 0.10)
    sshbrute_target = int(target_packets * 0.08)
    webbrute_target = int(target_packets * 0.05)

    # Benign phase: split across HTTP, DNS, SSH, ICMP
    # Each HTTP session is ~7 packets, DNS is 2, SSH session is ~6, ICMP pair is 2
    http_sessions = benign_target // 14   # half of benign as HTTP
    dns_pairs = benign_target // 8        # quarter as DNS
    ssh_sessions = benign_target // 16    # ~13% as SSH
    icmp_pairs = benign_target // 30      # ~7% as ICMP

    out.extend(gen_http(clk, http_sessions))
    out.extend(gen_dns(clk, dns_pairs))
    out.extend(gen_ssh(clk, ssh_sessions))
    out.extend(gen_icmp(clk, icmp_pairs))

    # Attack phases: vary slightly per file for realism
    out.extend(gen_ddos(clk, int(ddos_target * random.uniform(0.85, 1.15))))
    out.extend(gen_portscan(clk, int(portscan_target * random.uniform(0.85, 1.15))))
    out.extend(gen_ssh_brute(clk, max(10, int(sshbrute_target / 5))))  # 5 pkts/attempt
    out.extend(gen_web_brute(clk, max(10, int(webbrute_target / 6))))  # 6 pkts/attempt

    # More benign tail mixed in
    out.extend(gen_http(clk, http_sessions // 4))

    # Sort by time so timestamps are monotonic
    out.sort(key=lambda x: x[0])

    # Trim to target if we slightly overshot
    if len(out) > target_packets:
        out = out[:target_packets]

    return out


def write_atomic(path: Path, packets: List[Tuple[float, bytes]]) -> None:
    """Write to .tmp first then rename, so tcpreplay never sees a half-written file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    write_pcap(tmp, packets)
    tmp.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path("/pcaps/live.pcap"),
                        help="Output PCAP path")
    parser.add_argument("--packets", type=int, default=15000,
                        help="Packets per capture (default: 15000)")
    parser.add_argument("--interval", type=float, default=60.0,
                        help="Seconds between regenerations (default: 60)")
    parser.add_argument("--once", action="store_true",
                        help="Generate one PCAP then exit")
    args = parser.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)

    iteration = 0
    while True:
        iteration += 1
        # Use current real time as the pcap epoch so timestamps look sensible
        epoch = time.time()
        random.seed(int(epoch * 1000) ^ iteration)

        t0 = time.time()
        packets = build_capture(args.packets, epoch)
        write_atomic(args.out, packets)
        elapsed = time.time() - t0

        size_kb = args.out.stat().st_size / 1024
        msg = (f"[gen #{iteration}] wrote {len(packets):,} packets "
               f"({size_kb:.0f} KB) in {elapsed:.1f}s -> {args.out}")
        print(msg, flush=True)

        # Update stats file
        stats_path = args.out.parent / "stats.txt"
        with stats_path.open("w") as fh:
            fh.write(f"iteration: {iteration}\n")
            fh.write(f"timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
            fh.write(f"packets:   {len(packets)}\n")
            fh.write(f"size_kb:   {size_kb:.1f}\n")
            fh.write(f"path:      {args.out}\n")

        if args.once:
            break

        # Sleep for the rest of the interval
        sleep_time = max(1.0, args.interval - elapsed)
        time.sleep(sleep_time)


if __name__ == "__main__":
    main()
