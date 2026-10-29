#!/usr/bin/env python3
"""Generate test pcap with ICMPv4, ARP, ICMPv6 packets."""
import os
import struct

PCAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pcaps",
                    "icmp_arp_ipv6_test.pcap")

SEC = 1700000000

def make_eth(eptype=0x0800):
    return b'\x00\x11\x22\x33\x44\x55\x00\xaa\xbb\xcc\xdd\xee' + \
           struct.pack("!H", eptype)

def ip_hdr(src, dst, proto, plen):
    return struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 20+plen, 0x1234, 0, 64, proto, 0,
        bytes(map(int, src.split('.'))),
        bytes(map(int, dst.split('.'))))

def eth_arp(arp_opcode, sha, spa, tha, tpa):
    arp_body = (sha + spa +
                struct.pack("!HH", 1, 0x0800) +
                b'\x06\x04' +
                struct.pack("!H", arp_opcode) +
                tha + tpa)
    return make_eth(0x0806) + arp_body

pkts = []

# ARP Request
arp_req = eth_arp(1,
    b'\x00\xaa\xbb\xcc\xdd\x01', b'\xc0\xa8\x01\x0a',
    b'\x00\x00\x00\x00\x00\x00', b'\xc0\xa8\x01\x01')
pkts.append((SEC, arp_req))

# ARP Reply
arp_rep = eth_arp(2,
    b'\x00\x11\x22\x33\x44\x55', b'\xc0\xa8\x01\x01',
    b'\x00\x11\x22\x33\x44\x55', b'\xc0\xa8\x01\x0a')
pkts.append((SEC+1, arp_rep))

def ipv6_hdr(src6, dst6, payload_len):
    hdr = struct.pack("!IHBB", 0x60000000, payload_len, 58, 0xFF)
    return hdr + src6 + dst6

orig_udp = ip_hdr("10.0.0.1", "10.0.0.2", 17, 42) + struct.pack("!HHHH", 5000, 5001, 50, 0)

# ICMPv4 Echo Request
icmp_req = bytearray(12)
icmp_req[0] = 8   # type
icmp_req[1] = 0   # code
struct.pack_into("!H", icmp_req, 4, 1234)
struct.pack_into("!H", icmp_req, 6, 1)
icmp_req[8:12] = b"Hello "
pkt_req = make_eth() + ip_hdr("192.168.1.10", "8.8.8.8", 1, len(icmp_req)) + icmp_req
pkts.append((SEC+2, pkt_req))

# ICMPv4 Echo Reply
icmp_rep = bytearray(12)
icmp_rep[0] = 0   # type
icmp_rep[1] = 0   # code
struct.pack_into("!H", icmp_rep, 4, 1234)
struct.pack_into("!H", icmp_rep, 6, 1)
icmp_rep[8:12] = b"Hello "
pkt_rep = make_eth() + ip_hdr("8.8.8.8", "192.168.1.10", 1, len(icmp_rep)) + icmp_rep
pkts.append((SEC+3, pkt_rep))

# ICMPv4 Destination Unreachable
icmp_unreach = bytearray(8)
icmp_unreach[0] = 3   # type
icmp_unreach[1] = 3   # code
orig_ip = ip_hdr("10.0.0.1", "10.0.0.2", 17, 42)
struct.pack_into("!I", icmp_unreach, 4, 0)
icmp_unreach[4:8] = orig_ip[:4]
pkt_unreach = make_eth() + ip_hdr("10.0.0.2", "192.168.1.10", 1, len(icmp_unreach)) + icmp_unreach
pkts.append((SEC+4, pkt_unreach))

# ICMPv4 Time Exceeded
icmp_ttl = bytearray(8)
icmp_ttl[0] = 11   # type
icmp_ttl[1] = 0    # code
struct.pack_into("!I", icmp_ttl, 4, 0)
icmp_ttl[4:8] = orig_ip[:4]
pkt_ttl = make_eth() + ip_hdr("10.0.0.1", "192.168.1.10", 1, len(icmp_ttl)) + icmp_ttl
pkts.append((SEC+5, pkt_ttl))

# ICMPv6 NS
ns_target = bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01])
icmp6_ns = bytearray(24)  # type+code+checksum(4) + reserved(4) + target(16)
icmp6_ns[0] = 135
icmp6_ns[4:8] = b'\x00\x00\x00\x00'
icmp6_ns[8:24] = ns_target
src6 = ns_target
dst6 = bytes([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01])
ipv6_ns = ipv6_hdr(src6, dst6, 40 + len(icmp6_ns))
pkt_ns = make_eth(0x86dd) + ipv6_ns + icmp6_ns
pkts.append((SEC+6, pkt_ns))

# ICMPv6 NA
na_target = bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10])
icmp6_na = bytearray(24)  # type+code+checksum(4) + reserved(4) + target(16)
icmp6_na[0] = 136
struct.pack_into("!I", icmp6_na, 4, 0x60000000)  # S=1, R=1, O=1, reserved
icmp6_na[8:24] = na_target
ipv6_na = ipv6_hdr(na_target, src6, 40 + len(icmp6_na))
pkt_na = make_eth(0x86dd) + ipv6_na + icmp6_na
pkts.append((SEC+7, pkt_na))

# ICMPv6 RS
icmp6_rs = bytearray(20)
icmp6_rs[0] = 133
icmp6_rs[4:8] = b'\x00\x00\x00\x00'  # reserved(4)
rs_opt = struct.pack("!BB", 1, 1) + b'\x00\x11\x22\x33\x44\x55'
icmp6_rs[8:8+len(rs_opt)] = rs_opt
ipv6_rs = ipv6_hdr(src6, dst6, 40 + len(icmp6_rs))
pkt_rs = make_eth(0x86dd) + ipv6_rs + icmp6_rs
pkts.append((SEC+8, pkt_rs))

# ICMPv6 RA
# type(1)+code(1)+checksum(2)+CurHopLimit(1)+M(1)+O(1)+Res(1)+RouterLifetime(2)+ReachableTime(4)+RetransTime(4)=17 bytes, then options
icmp6_ra = bytearray(32)
icmp6_ra[0] = 134
icmp6_ra[4] = 0x60   # Cur Hop Limit
# M_flag(1) + O_flag(1) + Reserved(1) + Router_Lifetime(2) + Reachable_Time(4) + Retrans_Timer(4)
ra_flags = struct.pack("!HI", 0, 0)  # starts at offset 5
icmp6_ra[5:5+len(ra_flags)] = ra_flags
ra_opt = struct.pack("!BB", 1, 1)
icmp6_ra[17:17+len(ra_opt)] = ra_opt  # options start at offset 17
ipv6_ra = ipv6_hdr(na_target, src6, 40 + len(icmp6_ra))
pkt_ra = make_eth(0x86dd) + ipv6_ra + icmp6_ra
pkts.append((SEC+9, pkt_ra))

with open(PCAP, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ts, pkt in pkts:
        f.write(struct.pack("<IIII", ts, 0, len(pkt), len(pkt)))
        f.write(pkt)

with open(PCAP, "rb") as f:
    data = f.read()
off = 24
i = 0
ok = True
while off + 16 <= len(data):
    ts_s, ts_u, pl, ol = struct.unpack_from("<IIII", data, off)
    if pl == 0 or off + 16 + pl > len(data):
        print("ERROR pkt %d: off=%d plen=%d remaining=%d" % (i, off, pl, len(data)-off-16))
        ok = False
        break
    i += 1
    off += 16 + pl
print("Result: %d packets, %d bytes, verified=%s" % (i, len(data), ok))
