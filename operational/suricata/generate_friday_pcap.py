#!/usr/bin/env python3
"""
generate_friday_pcap.py
=======================

Generates a synthetic PCAP that mimics the traffic profile of the
CIC-IDS-2017 Friday afternoon capture. Uses scapy's packet construction
where it works, and falls back to direct libpcap binary writing so the
script never fails because of OS-specific IPv6 routing issues in scapy.

The output is written to /pcaps/sample.pcap (the path the docker-compose
file mounts into Suricata).

Traffic synthesised:
  * Benign HTTP/HTTPS request and response pairs
  * Benign DNS queries and responses
  * Benign SSH session
  * DDoS SYN flood from many spoofed sources
  * TCP SYN port scan
  * SSH brute force burst
  * HTTP brute force POST flood against /login
"""

from __future__ import annotations

import os
import random
import struct
import sys
from pathlib import Path
from typing import List, Tuple

# Avoid scapy's IPv6 routing probe which crashes in some Linux containers.
os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")

# Try to import scapy carefully. If anything fails, fall back to pure
# binary packet construction further below.
SCAPY_OK = False
try:
    import warnings
    warnings.filterwarnings("ignore")
    import logging
    logging.getLogger("scapy").setLevel(logging.CRITICAL)
    # Import only what we need from inet (the IPv6 layer is the troublemaker)
    import scapy.config as _scapy_config
    _scapy_config.conf.use_pcap = False
    # Block scapy.all from running its full module loader
    import importlib
    inet_mod = importlib.import_module("scapy.layers.inet")
    Ether = importlib.import_module("scapy.layers.l2").Ether
    IP = inet_mod.IP
    TCP = inet_mod.TCP
    UDP = inet_mod.UDP
    ICMP = inet_mod.ICMP
    Raw = importlib.import_module("scapy.packet").Raw
    SCAPY_OK = True
except Exception as _scapy_err:
    print(f"scapy import failed ({_scapy_err}); using pure-binary fallback",
          file=sys.stderr)
    SCAPY_OK = False


# ---------------------------------------------------------------------------
# Pure-binary packet construction fallback. Builds raw Ethernet frames with
# IPv4/TCP/UDP/ICMP headers. Slower than scapy but has no dependencies.
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


def _ip_header(src: str, dst: str, proto: int, payload_len: int, ttl: int = 64,
               ident: int = 0) -> bytes:
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    flags_frag = 0
    hdr = struct.pack("!BBHHHBBH4s4s",
                      version_ihl, tos, total_len, ident, flags_frag,
                      ttl, proto, 0,
                      _ip_to_bytes(src), _ip_to_bytes(dst))
    chk = _checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s",
                       version_ihl, tos, total_len, ident, flags_frag,
                       ttl, proto, chk,
                       _ip_to_bytes(src), _ip_to_bytes(dst))


def _tcp_header(src_ip: str, dst_ip: str, sport: int, dport: int,
                seq: int, ack: int, flags: int, window: int = 65535,
                payload: bytes = b"") -> bytes:
    data_offset_reserved = (5 << 4)
    hdr = struct.pack("!HHIIBBHHH",
                      sport, dport, seq, ack,
                      data_offset_reserved, flags, window, 0, 0)
    pseudo = (_ip_to_bytes(src_ip) + _ip_to_bytes(dst_ip) +
              struct.pack("!BBH", 0, 6, len(hdr) + len(payload)))
    chk = _checksum(pseudo + hdr + payload)
    return struct.pack("!HHIIBBHHH",
                       sport, dport, seq, ack,
                       data_offset_reserved, flags, window, chk, 0)


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


def _eth_header(src_mac: bytes, dst_mac: bytes, ethertype: int = 0x0800) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ethertype)


def make_tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
                    flags: str, seq: int = 0, ack: int = 0,
                    payload: bytes = b"") -> bytes:
    flag_map = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08,
                "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80}
    f = 0
    for c in flags:
        f |= flag_map.get(c, 0)
    tcp = _tcp_header(src_ip, dst_ip, sport, dport, seq, ack, f, 65535, payload)
    ip = _ip_header(src_ip, dst_ip, 6, len(tcp) + len(payload),
                    ident=random.randint(1, 65535))
    eth = _eth_header(b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02")
    return eth + ip + tcp + payload


def make_udp_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
                    payload: bytes) -> bytes:
    udp = _udp_header(src_ip, dst_ip, sport, dport, payload)
    ip = _ip_header(src_ip, dst_ip, 17, len(udp) + len(payload),
                    ident=random.randint(1, 65535))
    eth = _eth_header(b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02")
    return eth + ip + udp + payload


def make_icmp_packet(src_ip: str, dst_ip: str, itype: int = 8,
                     payload: bytes = b"abcdefghijklmnop") -> bytes:
    icmp = _icmp_header(itype, 0, 0x1234, 1, payload)
    ip = _ip_header(src_ip, dst_ip, 1, len(icmp) + len(payload),
                    ident=random.randint(1, 65535))
    eth = _eth_header(b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02")
    return eth + ip + icmp + payload


# ---------------------------------------------------------------------------
# Direct PCAP file writer (libpcap format)
# ---------------------------------------------------------------------------
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_ETHERNET = 1


def write_pcap(path: Path, packets: List[Tuple[float, bytes]]) -> None:
    """Write packets to a libpcap-format file.

    packets: list of (timestamp_seconds_float, raw_bytes) tuples.
    """
    with path.open("wb") as fh:
        # Global header
        fh.write(struct.pack("!IHHiIII",
                             PCAP_MAGIC,
                             PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
                             0,        # thiszone
                             0,        # sigfigs
                             65535,    # snaplen
                             PCAP_LINKTYPE_ETHERNET))
        for ts, data in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            fh.write(struct.pack("!IIII", sec, usec, len(data), len(data)))
            fh.write(data)


# ---------------------------------------------------------------------------
# Topology and clock
# ---------------------------------------------------------------------------
INTERNAL_NET = "192.168.10."
WEB_SERVER   = "192.168.10.50"
DB_SERVER    = "192.168.10.51"
DNS_SERVER   = "192.168.10.10"
GATEWAY      = "192.168.10.1"
CLIENTS = [f"{INTERNAL_NET}{i}" for i in range(20, 35)]

ATTACKER_PORTSCAN  = "172.16.0.5"
ATTACKER_BRUTE_SSH = "172.16.0.7"
ATTACKER_WEB_BRUTE = "172.16.0.9"

EXTERNAL_BENIGN = ["8.8.8.8", "1.1.1.1", "142.250.190.78", "151.101.1.69"]


class Clock:
    def __init__(self, start: float = 1745571600.0):  # 2025-04-25 09:00 UTC
        self.t = start

    def tick(self, dt: float = 0.001) -> float:
        self.t += dt
        return self.t


# ---------------------------------------------------------------------------
# Traffic generators (pure-binary; no scapy dependency)
# ---------------------------------------------------------------------------
def benign_http_session(clk: Clock, client: str, server: str,
                        sport: int) -> List[Tuple[float, bytes]]:
    pkts = []
    seq_c = random.randint(1000, 9999999)
    seq_s = random.randint(1000, 9999999)

    pkts.append((clk.tick(0.001), make_tcp_packet(client, server, sport, 80, "S", seq_c)))
    pkts.append((clk.tick(0.001), make_tcp_packet(server, client, 80, sport, "SA", seq_s, seq_c+1)))
    pkts.append((clk.tick(0.001), make_tcp_packet(client, server, sport, 80, "A", seq_c+1, seq_s+1)))

    request = (b"GET / HTTP/1.1\r\nHost: example.com\r\n"
               b"User-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n")
    pkts.append((clk.tick(0.005), make_tcp_packet(client, server, sport, 80, "PA",
                                                   seq_c+1, seq_s+1, request)))

    body = b"<html><body><h1>Welcome</h1></body></html>"
    response = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.20\r\n"
                b"Content-Type: text/html\r\n"
                b"Content-Length: " + str(len(body)).encode() +
                b"\r\n\r\n" + body)
    pkts.append((clk.tick(0.020), make_tcp_packet(server, client, 80, sport, "PA",
                                                   seq_s+1, seq_c+1+len(request), response)))

    pkts.append((clk.tick(0.005), make_tcp_packet(client, server, sport, 80, "FA",
                                                   seq_c+1+len(request), seq_s+1+len(response))))
    pkts.append((clk.tick(0.001), make_tcp_packet(server, client, 80, sport, "FA",
                                                   seq_s+1+len(response), seq_c+2+len(request))))
    return pkts


def benign_dns_query(clk: Clock, client: str, query_name: str) -> List[Tuple[float, bytes]]:
    """Build a minimal DNS query and a fixed-answer response."""
    pkts = []
    txid = random.randint(1, 65535)
    sport = random.randint(30000, 60000)

    # Encode query name
    qname = b""
    for label in query_name.strip(".").split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    # type A, class IN
    question = qname + struct.pack("!HH", 1, 1)
    # Query header: id, flags=0x0100 (recursion desired), qdcount=1
    query_payload = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    pkts.append((clk.tick(0.001),
                 make_udp_packet(client, DNS_SERVER, sport, 53, query_payload)))

    # Response: id, flags=0x8180, qdcount=1, ancount=1
    answer = qname + struct.pack("!HHIH", 1, 1, 60, 4) + _ip_to_bytes("93.184.216.34")
    response_payload = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer
    pkts.append((clk.tick(0.005),
                 make_udp_packet(DNS_SERVER, client, 53, sport, response_payload)))
    return pkts


def benign_ssh_session(clk: Clock, client: str, server: str,
                       sport: int) -> List[Tuple[float, bytes]]:
    pkts = []
    seq_c = random.randint(1000, 9999999)
    seq_s = random.randint(1000, 9999999)

    pkts.append((clk.tick(0.001), make_tcp_packet(client, server, sport, 22, "S", seq_c)))
    pkts.append((clk.tick(0.001), make_tcp_packet(server, client, 22, sport, "SA", seq_s, seq_c+1)))
    pkts.append((clk.tick(0.001), make_tcp_packet(client, server, sport, 22, "A", seq_c+1, seq_s+1)))

    banner_s = b"SSH-2.0-OpenSSH_8.9p1\r\n"
    banner_c = b"SSH-2.0-OpenSSH_8.9p1\r\n"
    pkts.append((clk.tick(0.020), make_tcp_packet(server, client, 22, sport, "PA",
                                                   seq_s+1, seq_c+1, banner_s)))
    pkts.append((clk.tick(0.020), make_tcp_packet(client, server, sport, 22, "PA",
                                                   seq_c+1, seq_s+1+len(banner_s), banner_c)))

    payload = bytes(random.randint(0, 255) for _ in range(120))
    pkts.append((clk.tick(0.030), make_tcp_packet(client, server, sport, 22, "PA",
                                                   seq_c+1+len(banner_c), seq_s+1+len(banner_s),
                                                   payload)))
    pkts.append((clk.tick(0.010), make_tcp_packet(client, server, sport, 22, "FA",
                                                   seq_c+1+len(banner_c)+len(payload),
                                                   seq_s+1+len(banner_s))))
    pkts.append((clk.tick(0.001), make_tcp_packet(server, client, 22, sport, "FA",
                                                   seq_s+1+len(banner_s),
                                                   seq_c+2+len(banner_c)+len(payload))))
    return pkts


def benign_icmp_echoes(clk: Clock, client: str, server: str,
                        n: int = 5) -> List[Tuple[float, bytes]]:
    pkts = []
    for i in range(n):
        pkts.append((clk.tick(0.5), make_icmp_packet(client, server, itype=8)))
        pkts.append((clk.tick(0.001), make_icmp_packet(server, client, itype=0)))
    return pkts


def ddos_syn_flood(clk: Clock, target: str,
                    n_packets: int = 800) -> List[Tuple[float, bytes]]:
    pkts = []
    sources = [f"172.16.{a}.{b}"
               for a in range(1, 6)
               for b in random.sample(range(2, 254), 25)]
    for _ in range(n_packets):
        src = random.choice(sources)
        sport = random.randint(1024, 65535)
        pkts.append((clk.tick(0.0005),
                     make_tcp_packet(src, target, sport, 80, "S",
                                     seq=random.randint(1, 999999))))
    return pkts


def port_scan(clk: Clock, attacker: str, target: str,
              n_ports: int = 200) -> List[Tuple[float, bytes]]:
    pkts = []
    sport_base = random.randint(40000, 50000)
    ports = random.sample(range(1, 1024), min(n_ports, 1023))
    for i, p in enumerate(ports):
        pkts.append((clk.tick(0.002),
                     make_tcp_packet(attacker, target,
                                     sport_base + (i % 1000), p, "S",
                                     seq=random.randint(1, 999999))))
        if random.random() < 0.4:
            pkts.append((clk.tick(0.001),
                         make_tcp_packet(target, attacker, p,
                                         sport_base + (i % 1000), "RA")))
    return pkts


def ssh_brute_force(clk: Clock, attacker: str, target: str,
                    n_attempts: int = 30) -> List[Tuple[float, bytes]]:
    pkts = []
    for _ in range(n_attempts):
        sport = random.randint(40000, 60000)
        seq_c = random.randint(1000, 9999999)
        seq_s = random.randint(1000, 9999999)
        pkts.append((clk.tick(0.05), make_tcp_packet(attacker, target, sport, 22, "S", seq_c)))
        pkts.append((clk.tick(0.005), make_tcp_packet(target, attacker, 22, sport, "SA", seq_s, seq_c+1)))
        pkts.append((clk.tick(0.002), make_tcp_packet(attacker, target, sport, 22, "A", seq_c+1, seq_s+1)))
        banner = b"SSH-2.0-OpenSSH_8.9p1\r\n"
        pkts.append((clk.tick(0.010), make_tcp_packet(target, attacker, 22, sport, "PA",
                                                       seq_s+1, seq_c+1, banner)))
        pkts.append((clk.tick(0.020), make_tcp_packet(target, attacker, 22, sport, "FA",
                                                       seq_s+1+len(banner), seq_c+1)))
    return pkts


def web_brute_force(clk: Clock, attacker: str, target: str,
                    n_attempts: int = 25) -> List[Tuple[float, bytes]]:
    pkts = []
    for i in range(n_attempts):
        sport = random.randint(40000, 60000)
        seq_c = random.randint(1000, 9999999)
        seq_s = random.randint(1000, 9999999)

        pkts.append((clk.tick(0.001), make_tcp_packet(attacker, target, sport, 80, "S", seq_c)))
        pkts.append((clk.tick(0.001), make_tcp_packet(target, attacker, 80, sport, "SA", seq_s, seq_c+1)))
        pkts.append((clk.tick(0.001), make_tcp_packet(attacker, target, sport, 80, "A", seq_c+1, seq_s+1)))

        body = f"username=admin&password=guess{i}".encode()
        request = (b"POST /login HTTP/1.1\r\n"
                   b"Host: target.local\r\n"
                   b"Content-Type: application/x-www-form-urlencoded\r\n"
                   b"Content-Length: " + str(len(body)).encode() +
                   b"\r\n\r\n" + body)
        pkts.append((clk.tick(0.020), make_tcp_packet(attacker, target, sport, 80, "PA",
                                                       seq_c+1, seq_s+1, request)))
        resp = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
        pkts.append((clk.tick(0.030), make_tcp_packet(target, attacker, 80, sport, "PA",
                                                       seq_s+1, seq_c+1+len(request), resp)))
        pkts.append((clk.tick(0.005), make_tcp_packet(attacker, target, sport, 80, "FA",
                                                       seq_c+1+len(request), seq_s+1+len(resp))))
    return pkts


# ---------------------------------------------------------------------------
# Compose the capture
# ---------------------------------------------------------------------------
def build_capture(seed: int = 42) -> List[Tuple[float, bytes]]:
    random.seed(seed)
    clk = Clock()
    all_pkts: List[Tuple[float, bytes]] = []

    # Phase 1: benign baseline
    for _ in range(60):
        client = random.choice(CLIENTS)
        server = random.choice([WEB_SERVER] + EXTERNAL_BENIGN[:3])
        all_pkts.extend(benign_http_session(clk, client, server,
                                            random.randint(40000, 60000)))

    domains = ["example.com", "google.com", "ubuntu.com", "github.com",
               "wikipedia.org", "cloudflare.com"]
    for _ in range(30):
        all_pkts.extend(benign_dns_query(clk, random.choice(CLIENTS),
                                         random.choice(domains)))

    for _ in range(8):
        all_pkts.extend(benign_ssh_session(clk, random.choice(CLIENTS),
                                            DB_SERVER,
                                            random.randint(40000, 60000)))

    all_pkts.extend(benign_icmp_echoes(clk, CLIENTS[0], GATEWAY, n=5))

    # Phase 2: DDoS
    all_pkts.extend(ddos_syn_flood(clk, WEB_SERVER, n_packets=800))

    # Phase 3: more benign
    for _ in range(20):
        all_pkts.extend(benign_http_session(clk, random.choice(CLIENTS),
                                            random.choice(EXTERNAL_BENIGN),
                                            random.randint(40000, 60000)))

    # Phase 4: port scan
    all_pkts.extend(port_scan(clk, ATTACKER_PORTSCAN, WEB_SERVER, n_ports=200))

    # Phase 5: SSH brute force
    all_pkts.extend(ssh_brute_force(clk, ATTACKER_BRUTE_SSH, DB_SERVER,
                                     n_attempts=30))

    # Phase 6: web brute force
    all_pkts.extend(web_brute_force(clk, ATTACKER_WEB_BRUTE, WEB_SERVER,
                                     n_attempts=25))

    # Phase 7: tail of benign traffic
    for _ in range(15):
        all_pkts.extend(benign_http_session(clk, random.choice(CLIENTS),
                                            random.choice(EXTERNAL_BENIGN),
                                            random.randint(40000, 60000)))

    all_pkts.sort(key=lambda x: x[0])
    return all_pkts


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/pcaps/sample.pcap")
    out.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generating synthetic Friday-style PCAP -> {out}")
    pkts = build_capture(seed=42)
    print(f"Total packets: {len(pkts)}")
    write_pcap(out, pkts)

    size_kb = out.stat().st_size / 1024
    print(f"Wrote {size_kb:.1f} KB to {out}")
    print()
    print("Traffic profile:")
    print("  - Benign HTTP, DNS, SSH, ICMP baseline traffic")
    print(f"  - DDoS SYN flood -> {WEB_SERVER}:80")
    print(f"  - Port scan from {ATTACKER_PORTSCAN} -> {WEB_SERVER}")
    print(f"  - SSH brute force from {ATTACKER_BRUTE_SSH} -> {DB_SERVER}:22")
    print(f"  - Web brute force POST flood from {ATTACKER_WEB_BRUTE} -> /login")


if __name__ == "__main__":
    main()
