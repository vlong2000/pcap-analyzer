#!/usr/bin/env python3
"""Generate test pcap with RTP/RTCP/SIP packets."""
import os
import struct

PCAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pcaps",
                    "rtp_rtcp_test.pcap")

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

pkts = []

# ===== RTP Audio (PCMU, SSRC=0xDEADBEEF, seq 1000-1002) =====
for i in range(3):
    hdr = struct.pack("!IIII", (0x80<<24)|(1000+i), 8000+i*160, 0xDEADBEEF, 0)
    pkts.append((SEC+i, eth_udp(5004, 5004, hdr + b'\x00'*160)))

# ===== RTP Video (H264, SSRC=0xCAFE0001, seq 2000-2001) =====
for i in range(2):
    hdr = struct.pack("!IIII", (0x80<<24)|(96<<16)|(2000+i), 90000+i*3000, 0xCAFE0001, 0)
    ext = struct.pack("!HH", 0x1000, 1) + struct.pack("!I", 1)
    pay = b'\x18\x01\x00\x00' + b'\xff'*100
    pkts.append((SEC+5+i, eth_udp(5004, 5004, hdr + ext + pay)))

# ===== RTCP SR (Type=200) =====
# Format: VPT(1)+length(1) | SSRC(4) | NTP hi(4)+NTP lo(4) | RTP-ts(4) | pkt-count(4) | byte-count(4)
#        | SSRC(4) | frac+lost(4) | last-seq(4) | jitter(4) | LSR(4) | DLSR(4)
sr = bytearray(52)  # SR: 13 x 32-bit words = 52 bytes
sr[0] = 0x81  # V=2, Count=1
sr[1] = 192  # SR
# length=13 (14 words-1)
struct.pack_into("!H", sr, 2, 13)
struct.pack_into("!I", sr, 4, 0xDEADBEEF)  # SSRC
# NTP (high, low)
struct.pack_into("!I", sr, 8, 0x836A2660)  # high 32 bits
struct.pack_into("!I", sr, 12, 0)  # low 32 bits
# RTP ts, pkt count, byte count
struct.pack_into("!I", sr, 16, 600)
struct.pack_into("!I", sr, 20, 320)
struct.pack_into("!I", sr, 24, 1280)
# RR block
struct.pack_into("!I", sr, 28, 0xCAFE0001)  # SSRC of RTP source
struct.pack_into("!I", sr, 32, 0)  # frac lost + cumulative lost
struct.pack_into("!I", sr, 36, 0x03E8)  # last seq
struct.pack_into("!I", sr, 40, 0)  # jitter
struct.pack_into("!I", sr, 44, 0)  # LSR
struct.pack_into("!I", sr, 48, 0)  # DLSR
pkts.append((SEC+10, eth_udp(5005, 5005, bytes(sr))))

# ===== RTCP RR (Type=193) =====
# RR body: SSRC(4) + src(4) + frac_lost+lost(4) + last_seq(4) + jitter(4) + LSR(4) + DLSR(4)
# = 7 x 32-bit words = 28 bytes body + 4 bytes header = 32 bytes total
rr = bytearray(32)
rr[0] = 0x80  # V=2, Count=0
rr[1] = 193   # RR
struct.pack_into("!H", rr, 2, 7)  # length=7 (8 words-1)
struct.pack_into("!I", rr, 4, 0xDEADBEEF)  # SSRC of sender
struct.pack_into("!I", rr, 8, 0xCAFE0001)  # SSRC of RTP source
struct.pack_into("!I", rr, 12, 0)          # frac lost + cumulative lost
struct.pack_into("!I", rr, 16, 0x03E8)     # last seq
struct.pack_into("!I", rr, 20, 100)        # jitter
struct.pack_into("!I", rr, 24, 0)          # LSR
struct.pack_into("!I", rr, 28, 32)         # DLSR
pkts.append((SEC+12, eth_udp(5005, 5005, bytes(rr))))

# ===== RTCP BYE (Type=195) =====
# header(4) + body = 20 bytes (SSRC+RC+reason_ssrc+len+reason)
by_body = bytearray(20)  # SSRC(4) + RC(1) + reason_ssrc(4) + len(1) + reason(10)
struct.pack_into("!I", by_body, 0, 0xDEADBEEF)  # SSRC
by_body[4] = 1  # RC=1
struct.pack_into("!I", by_body, 5, 0xCAFE0001)  # reason SSRC
by_body[9] = 6  # len("Bye!")
by_body[10:16] = b"Bye!"
by = bytearray(4)
by[0] = 0x80
by[1] = 195
struct.pack_into("!H", by, 2, len(by_body)//4)
full_bye = bytes(by) + bytes(by_body)
pkts.append((SEC+14, eth_udp(5005, 5005, full_bye)))

# ===== RTCP SDES (Type=194) =====
# SDP header (4 bytes) + SSRC (4 bytes) + body = 12 bytes total
# body = SSRC(4) + type(1) + len(1) + cname(17) + end(1) = 24 bytes
sd = bytearray(16)  # header + SSRC + 8 bytes
sd[0] = 0x80  # V=2, Count=0
sd[1] = 194  # SDES
sdes_body = bytearray(24)  # SSRC(4) + type(1) + len(1) + cname(17) + end(1) = 24
struct.pack_into("!I", sdes_body, 0, 0xDEADBEEF)  # SSRC
sdes_body[4] = 1  # CNAME item type
sdes_body[5] = 17  # length
sdes_body[6:23] = b"alice@example.com"  # CNAME
sdes_body[23] = 0  # end
# Combine header + body
sd = bytearray(4)  # VPT(1) + length(1) + len(2)
sd[0] = 0x80
sd[1] = 194
struct.pack_into("!H", sd, 2, len(sdes_body)//4)
full_sdes = bytes(sd) + sdes_body
pkts.append((SEC+16, eth_udp(5005, 5005, full_sdes)))

# ===== RTCP APP (Type=207) =====
# header(4) + body = 8 bytes (2 x 32-bit words)
app_body = bytearray(8)
struct.pack_into("!I", app_body, 0, 0xDEADBEEF)  # SSRC
struct.pack_into("!I", app_body, 4, int.from_bytes(b"APPV", 'big'))
sd = bytearray(4)
sd[0] = 0x80
sd[1] = 207
struct.pack_into("!H", sd, 2, len(app_body)//4)
full_app = bytes(sd) + app_body
pkts.append((SEC+18, eth_udp(5005, 5005, full_app)))

# ===== SIP INVITE + SDP =====
sip_inv = (
    b"INVITE sip:bob@10.0.0.1 SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n"
    b"From: Alice <sip:alice@192.168.1.10>\r\n"
    b"To: Bob <sip:bob@10.0.0.1>\r\n"
    b"Call-ID: test123@192.168.1.10\r\n"
    b"CSeq: 1 INVITE\r\n"
    b"Contact: <sip:alice@192.168.1.10>\r\n"
    b"Content-Type: application/sdp\r\n"
)
sdp1 = (
    b"v=0\r\n"
    b"o=alice 2890844526 2890844526 IN IP4 192.168.1.10\r\n"
    b"s=-\r\n"
    b"c=IN IP4 192.168.1.10\r\n"
    b"t=0 0\r\n"
    b"m=audio 5004 RTP/AVP 0 8 18\r\n"
    b"a=rtpmap:0 PCMU/8000\r\n"
    b"a=rtpmap:8 PCMA/8000\r\n"
    b"a=rtpmap:18 G729/8000\r\n"
    b"a=rtcp:5005 IN IP4 192.168.1.10\r\n"
)
cl = b"Content-Length: " + str(len(sdp1)).encode() + b"\r\n"
sip_inv += cl + b"\r\n" + sdp1
pkts.append((SEC+20, eth_udp(5060, 5060, sip_inv)))

# ===== SIP 200 OK + SDP =====
sip_ok = (
    b"SIP/2.0 200 OK\r\n"
    b"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n"
    b"From: Alice <sip:alice@192.168.1.10>\r\n"
    b"To: Bob <sip:bob@10.0.0.1>\r\n"
    b"Call-ID: test123@192.168.1.10\r\n"
    b"CSeq: 1 INVITE\r\n"
    b"Contact: <sip:bob@10.0.0.1>\r\n"
    b"Content-Type: application/sdp\r\n"
)
sdp2 = (
    b"v=0\r\n"
    b"o=bob 2890844526 2890844526 IN IP4 10.0.0.1\r\n"
    b"s=-\r\n"
    b"c=IN IP4 10.0.0.1\r\n"
    b"t=0 0\r\n"
    b"m=audio 6004 RTP/AVP 0 18\r\n"
    b"a=rtpmap:0 PCMU/8000\r\n"
    b"a=rtpmap:18 G729/8000\r\n"
    b"a=rtcp:6005 IN IP4 10.0.0.1\r\n"
    b"m=video 7004 RTP/AVP 96\r\n"
    b"a=rtpmap:96 H264/90000\r\n"
    b"a=fmtp:96 level-asymmetry-allowed=1\r\n"
)
cl = b"Content-Length: " + str(len(sdp2)).encode() + b"\r\n"
sip_ok += cl + b"\r\n" + sdp2
pkts.append((SEC+21, eth_udp(5060, 5060, sip_ok)))

# ===== SIP BYE =====
sip_bye = (
    b"BYE sip:bob@10.0.0.1 SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n"
    b"From: Alice <sip:alice@192.168.1.10>\r\n"
    b"To: Bob <sip:bob@10.0.0.1>\r\n"
    b"Call-ID: test123@192.168.1.10\r\n"
    b"CSeq: 2 BYE\r\n"
    b"\r\n"
)
pkts.append((SEC+22, eth_udp(5060, 5060, sip_bye)))

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
        print("  raw:", data[off:off+16].hex())
        ok = False
        break
    i += 1
    off += 16 + pl
print("Result: %d packets, %d bytes, verified=%s" % (i, len(data), ok))
