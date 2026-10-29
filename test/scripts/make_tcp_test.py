#!/usr/bin/env python3
"""Generate test pcap with TCP SIP (pipeline) and HTTP packets."""
import os
import struct

PCAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pcaps", "tcp_test.pcap")

SEC = 1700000000

def make_eth():
    return b'\x00\x11\x22\x33\x44\x55\x00\xaa\xbb\xcc\xdd\xee\x08\x00'

def ip_hdr(src, dst, proto, plen):
    return struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 20+plen, 0x1234, 0, 64, proto, 0,
        bytes(map(int, src.split('.'))),
        bytes(map(int, dst.split('.'))))

def tcp_hdr(sp, dp, seq, ack, data_off_flags, payload=b''):
    hlen = 5
    tcp_len = 20 + len(payload)
    # data_off_flags: 4 bits data offset + 3 bits reserved + 9 bits flags
    flags = data_off_flags & 0x1FF
    d_off = (data_off_flags & 0xF0)  # keep flags in bits 4-11
    hdr = struct.pack("!HHIIHHHH", sp, dp, seq, ack, d_off | (hlen << 12),
                       65535, 0, 0)
    return hdr + payload

def eth_tcp(sport, dport, seq, ack, flags, payload=b''):
    eth = make_eth()
    ip = ip_hdr("192.168.1.10", "10.0.0.1", 6, 20+len(payload))
    tcp = tcp_hdr(sport, dport, seq, ack, 5, payload)
    return eth + ip + tcp

pkts = []
SEQ_A = 1000
SEQ_B = 5000

# ===== TCP 粘包: 两条 SIP 消息粘在一起 =====
sip_msg1 = (
    b"INVITE sip:bob@10.0.0.1 SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n"
    b"From: Alice <sip:alice@192.168.1.10>\r\n"
    b"To: Bob <sip:bob@10.0.0.1>\r\n"
    b"Call-ID: tcp-test@192.168.1.10\r\n"
    b"CSeq: 1 INVITE\r\n"
    b"Contact: <sip:alice@192.168.1.10>\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)
sip_msg2 = (
    b"ACK sip:bob@10.0.0.1 SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n"
    b"From: Alice <sip:alice@192.168.1.10>\r\n"
    b"To: Bob <sip:bob@10.0.0.1>\r\n"
    b"Call-ID: tcp-test@192.168.1.10\r\n"
    b"CSeq: 1 ACK\r\n"
    b"\r\n"
)
piped_sip = sip_msg1 + sip_msg2
pkts.append((SEC, eth_tcp(5060, 5060, SEQ_A, 2000, 0x018, piped_sip)))

# ===== HTTP GET 请求 =====
http_get = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: www.example.com\r\n"
    b"User-Agent: Mozilla/5.0\r\n"
    b"Accept: text/html\r\n"
    b"Connection: keep-alive\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)
pkts.append((SEC+1, eth_tcp(12345, 80, SEQ_A, 3000, 0x018, http_get)))

# ===== HTTP POST 请求 (JSON body) =====
post_body = b'{"name":"alice","action":"login"}'
http_post = (
    b"POST /api/login HTTP/1.1\r\n"
    b"Host: api.example.com\r\n"
    b"User-Agent: test-client/1.0\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(post_body)).encode() + b"\r\n"
    b"Connection: close\r\n"
    b"\r\n"
) + post_body
pkts.append((SEC+2, eth_tcp(12346, 8080, SEQ_A, 4000, 0x018, http_post)))

# ===== HTTP 200 OK 响应 =====
http_body = b"<!DOCTYPE html><html><head><title>Hello</title></head><body><p>Welcome</p></body></html>"
http_200 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Date: Mon, 15 Nov 2023 06:13:00 GMT\r\n"
    b"Server: Apache/2.4.41\r\n"
    b"Content-Type: text/html; charset=UTF-8\r\n"
    b"Content-Length: " + str(len(http_body)).encode() + b"\r\n"
    b"Set-Cookie: session=abc123; Path=/\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
) + http_body
pkts.append((SEC+3, eth_tcp(80, 12345, SEQ_B, 4500, 0x018, http_200)))

# ===== HTTP 301 重定向 =====
http_301 = (
    b"HTTP/1.1 301 Moved Permanently\r\n"
    b"Date: Mon, 15 Nov 2023 06:13:01 GMT\r\n"
    b"Server: nginx/1.18\r\n"
    b"Location: https://www.example.com/\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)
pkts.append((SEC+4, eth_tcp(80, 12345, SEQ_B+1, 4500, 0x018, http_301)))

# ===== HTTP 404 响应 =====
http_body_404 = b"404 - Page Not Found"
http_404 = (
    b"HTTP/1.1 404 Not Found\r\n"
    b"Date: Mon, 15 Nov 2023 06:13:02 GMT\r\n"
    b"Server: nginx/1.18\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: " + str(len(http_body_404)).encode() + b"\r\n"
    b"Connection: close\r\n"
    b"\r\n"
) + http_body_404
pkts.append((SEC+5, eth_tcp(80, 12346, SEQ_B+2, 4500, 0x018, http_404)))

# ===== HTTP 响应体: XML =====
xml_body = b"<?xml version='1.0'?><response><status>ok</status><count>42</count></response>"
http_200_xml = (
    b"HTTP/1.1 200 OK\r\n"
    b"Date: Mon, 15 Nov 2023 06:13:03 GMT\r\n"
    b"Server: Go\r\n"
    b"Content-Type: application/xml\r\n"
    b"Content-Length: " + str(len(xml_body)).encode() + b"\r\n"
    b"\r\n"
) + xml_body
pkts.append((SEC+6, eth_tcp(8080, 12346, SEQ_B+3, 4500, 0x018, http_200_xml)))

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
