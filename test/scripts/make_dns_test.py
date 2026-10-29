#!/usr/bin/env python3
"""Generate test pcap with DNS query and response packets."""
import os
import struct

PCAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pcaps", "dns_test.pcap")

SEC = 1700000000

def make_eth():
    return b'\x00\x11\x22\x33\x44\x55\x00\xaa\xbb\xcc\xdd\xee\x08\x00'

def ip_hdr(src, dst, proto, plen):
    return struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 20+plen, 0x1234, 0, 64, proto, 0,
        bytes(map(int, src.split('.'))),
        bytes(map(int, dst.split('.'))))

def udp_hdr(sp, dp, ulen):
    return struct.pack("!HHHH", sp, dp, ulen, 0)

def eth_udp(sport, dport, payload):
    eth = make_eth()
    ip = ip_hdr("192.168.1.10", "10.0.0.1", 17, 8+len(payload))
    udp = udp_hdr(sport, dport, 8+len(payload))
    return eth + ip + udp + payload

def dns_name(name):
    """编码 DNS 域名。"""
    parts = name.split('.')
    result = b''
    for part in parts:
        result += bytes([len(part)]) + part.encode('ascii')
    return result + b'\x00'

def dns_query(txn_id, domain, qtype, qclass=1):
    """构造简单 DNS 查询。"""
    # flags: QR=0(查询) + 0000 opcode + AA=0 + TC=0 + RD=1 + RA=0 + Z=0 + rcode=0000
    flags = 0x0100
    hdr = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)
    return hdr + dns_name(domain) + struct.pack("!HH", qtype, qclass)

def dns_response(txn_id, domain, qtype=1, answers=None):
    """构造 DNS 响应。
    answers: list of (type, class, ttl, rdata)
    rdata depends on type:
      A(1) = 4 bytes IP
      AAAA(28) = 16 bytes IPv6
      CNAME(5) = domain name
      MX(15) = priority(2) + domain
      TXT(16) = length(1) + text
    """
    flags = 0x8180  # QR=1, RD=1, RA=1, RCODE=0
    nanswer = len(answers) if answers else 0
    hdr = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, nanswer)
    buf = hdr + dns_name(domain)
    if qtype is not None:
        buf += struct.pack("!HH", qtype, 1)

    for a in (answers or []):
        atype, aclass, attl, ardata = a
        # name pointer to domain (offset 0)
        buf += b'\xc0\x0c'
        buf += struct.pack("!HHIH", atype, aclass, attl, len(ardata))
        buf += ardata
    return buf

pkts = []

# ===== DNS 查询: A record (www.example.com) =====
txn_id = 0x1234
qry = dns_query(txn_id, "www.example.com", 1)  # QTYPE=A
pkts.append((SEC, eth_udp(55000, 53, qry)))

# ===== DNS 响应: A record =====
ip_bytes = bytes([93, 184, 216, 34])  # 93.184.216.34
ans_a = dns_response(txn_id, "www.example.com", 1, [
    (1, 1, 300, ip_bytes)  # A, 300s TTL
])
pkts.append((SEC+1, eth_udp(53, 55000, ans_a)))

# ===== DNS 查询: AAAA record =====
txn_id2 = 0x5678
qry6 = dns_query(txn_id2, "ipv6.google.com", 28)  # QTYPE=AAAA
pkts.append((SEC+2, eth_udp(55001, 53, qry6)))

# ===== DNS 响应: AAAA record =====
ip6 = bytes([0x26, 0x07, 0xfe, 0xc0, 0xde, 0x01, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
ans6 = dns_response(txn_id2, "ipv6.google.com", 28, [
    (28, 1, 600, ip6)  # AAAA, 600s TTL
])
pkts.append((SEC+3, eth_udp(53, 55001, ans6)))

# ===== DNS 查询: CNAME =====
txn_id3 = 0x9abc
qry_cname = dns_query(txn_id3, "www.wikipedia.org", 5)  # QTYPE=CNAME
pkts.append((SEC+4, eth_udp(55002, 53, qry_cname)))

# ===== DNS 响应: CNAME =====
ans_cname = dns_response(txn_id3, "www.wikipedia.org", 5, [
    (5, 1, 3600, dns_name("en.wikipedia.org"))  # CNAME
])
pkts.append((SEC+5, eth_udp(53, 55002, ans_cname)))

# ===== DNS 查询: MX record =====
txn_id4 = 0xdef0
qry_mx = dns_query(txn_id4, "gmail.com", 15)  # QTYPE=MX
pkts.append((SEC+6, eth_udp(55003, 53, qry_mx)))

# ===== DNS 响应: MX record =====
mx_data = struct.pack("!H", 10) + dns_name("gmail-smtp-in.l.google.com")
ans_mx = dns_response(txn_id4, "gmail.com", 15, [
    (15, 1, 3600, mx_data)  # MX, priority=10
])
pkts.append((SEC+7, eth_udp(53, 55003, ans_mx)))

# ===== DNS 查询: TXT record =====
txn_id5 = 0xb1b1
qry_txt = dns_query(txn_id5, "example.com", 16)  # QTYPE=TXT
pkts.append((SEC+8, eth_udp(55004, 53, qry_txt)))

# ===== DNS 响应: TXT record =====
txt_val = b"v=spf1 include:_spf.example.com ~all"
ans_txt = dns_response(txn_id5, "example.com", 16, [
    (16, 1, 3600, bytes([len(txt_val)]) + txt_val)  # TXT
])
pkts.append((SEC+9, eth_udp(53, 55004, ans_txt)))

# ===== DNS 查询: 不存在的域名 (NXDOMAIN) =====
txn_id6 = 0xdead
qry_nx = dns_query(txn_id6, "definitely-not-real-12345.com", 1)
pkts.append((SEC+10, eth_udp(55005, 53, qry_nx)))

# ===== DNS 响应: NXDOMAIN (RCODE=3) =====
flags = 0x8183  # QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
hdr_nx = struct.pack("!HHHHHH", txn_id6, flags, 1, 0, 0, 0)
ans_nx = hdr_nx + dns_name("definitely-not-real-12345.com") + struct.pack("!HH", 1, 1)
pkts.append((SEC+11, eth_udp(53, 55005, ans_nx)))

# ===== DNS 查询: 多个 answer =====
txn_id7 = 0xbeef
qry_multi = dns_query(txn_id7, "example.org", 1)
pkts.append((SEC+12, eth_udp(55006, 53, qry_multi)))

# ===== DNS 响应: 多个 A record =====
ans_multi = dns_response(txn_id7, "example.org", 1, [
    (1, 1, 120, bytes([93, 184, 215, 1])),
    (1, 1, 120, bytes([93, 184, 215, 2])),
])
pkts.append((SEC+13, eth_udp(53, 55006, ans_multi)))

# =========== Write pcap ===========
with open(PCAP, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ts, pkt in pkts:
        f.write(struct.pack("<IIII", ts, 0, len(pkt), len(pkt)))
        f.write(pkt)

# =========== Verify ===========
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
