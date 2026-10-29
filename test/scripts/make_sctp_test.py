#!/usr/bin/env python3
"""Generate test pcap with SCTP packets."""
import os
import struct

PCAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pcaps", "sctp_test.pcap")

SEC = 1700000000

def make_eth():
    return b'\x00\x11\x22\x33\x44\x55\x00\xaa\xbb\xcc\xdd\xee\x08\x00'

def ip_hdr(src, dst, proto, plen):
    return struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 20+plen, 0x1234, 0, 64, proto, 0,
        bytes(map(int, src.split('.'))),
        bytes(map(int, dst.split('.'))))

def sctp_hdr(sport, dport, vtag, payload=b''):
    return struct.pack("!HHII", sport, dport, vtag, 0) + payload

def sctp_chunk(chunk_type, chunk_flags, chunk_body):
    clen = len(chunk_body) + 4
    clen = (clen + 3) & ~3
    body_len = clen - 4
    hdr = struct.pack("!BBH", chunk_type, chunk_flags, clen)
    body_padded = chunk_body + b'\x00' * (body_len - len(chunk_body))
    return hdr + body_padded

def eth_sctp(sport, dport, vtag, chunks):
    eth = make_eth()
    chunk_data = b''
    for c in chunks:
        chunk_data += c
    ip_len = 12 + len(chunk_data)
    ip = ip_hdr("192.168.1.10", "10.0.0.1", 132, ip_len)
    sctp = sctp_hdr(sport, dport, vtag, chunk_data)
    return eth + ip + sctp

pkts = []

# INIT: init_tag(4)+a_rwnd(4)+os(2)+is(2)+init_tsn(4) = 16 bytes
init_body = struct.pack("!IIHHI", 0x12345678, 0x00FFFFFF, 3, 3, 3)
init_hdr = sctp_chunk(1, 0, init_body)
pkts.append((SEC, eth_sctp(3000, 3000, 0, [init_hdr])))

# INIT_ACK: init_tag(4)+a_rwnd(4)+init_tsn(4)+os(2)+is(2) = 16 bytes
initack_body = struct.pack("!IIHIH", 0x87654321, 0x00FFFFFF, 1, 1, 1)
initack_hdr = sctp_chunk(2, 0, initack_body)
pkts.append((SEC+1, eth_sctp(3000, 3000, 0x12345678, [initack_hdr])))

# COOKIE_ECHO
cookie_body = b'\x00' * 20
cookie_hdr = sctp_chunk(10, 0, b'cookie-data-for-handshake-1234' + cookie_body)
pkts.append((SEC+2, eth_sctp(3000, 3000, 0x87654321, [cookie_hdr])))

# COOKIE_ACK
cookie_ack_hdr = sctp_chunk(11, 0, b'')
pkts.append((SEC+3, eth_sctp(3000, 3000, 0x00000000, [cookie_ack_hdr])))

# DATA: TSN(4)+SID(2)+SSN(2)+PPID(4)+payload
data_body = struct.pack("!IHHI", 1, 0, 0, 62) + b'ASAP payload data'
data_hdr = sctp_chunk(0, 0, data_body)
pkts.append((SEC+4, eth_sctp(3000, 3000, 0x87654321, [data_hdr])))

# SACK: cum_tsn(4)+a_rwnd(4)+n_gap_blocks(2)+n_dup_tsns(2)
sack_body = struct.pack("!IIHH", 1, 1048575, 0, 0)
sack_hdr = sctp_chunk(3, 0, sack_body)
pkts.append((SEC+5, eth_sctp(3000, 3000, 0, [sack_hdr])))

# DATA stream=1, ssn=1
data2_body = struct.pack("!IHHI", 2, 1, 1, 0) + b'Second DATA payload'
data2_hdr = sctp_chunk(0, 0, data2_body)
pkts.append((SEC+6, eth_sctp(3000, 3000, 0x87654321, [data2_hdr])))

# HEARTBEAT: param_type(2)+param_length(2)+value
hb_param = struct.pack("!HH", 1, 12) + b'heartbeat\x00'
hb_hdr = sctp_chunk(4, 0, hb_param)
pkts.append((SEC+7, eth_sctp(3000, 3000, 0x87654321, [hb_hdr])))

# HEARTBEAT_ACK
hback_hdr = sctp_chunk(5, 0, hb_param)
pkts.append((SEC+8, eth_sctp(3000, 3000, 0, [hback_hdr])))

# Multiple DATA in one packet
d1 = struct.pack("!IHHI", 3, 0, 2, 0) + b'Multi-data 1'
d2 = struct.pack("!IHHI", 4, 2, 0, 0) + b'Multi-data 2'
multi_hdr = sctp_chunk(0, 0, d1) + sctp_chunk(0, 0, d2)
pkts.append((SEC+9, eth_sctp(3000, 3000, 0x87654321, [multi_hdr])))

# SHUTDOWN: cum_tsn(4)
shutdown_body = struct.pack("!I", 4)
shutdown_hdr = sctp_chunk(7, 0, shutdown_body)
pkts.append((SEC+10, eth_sctp(3000, 3000, 0x87654321, [shutdown_hdr])))

# SHUTDOWN_ACK
shutdownack_hdr = sctp_chunk(8, 0, shutdown_body)
pkts.append((SEC+11, eth_sctp(3000, 3000, 0, [shutdownack_hdr])))

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
