# -*- coding: utf-8 -*-
"""生成带 DNS/HTTP/RTP/RTCP 的测试 pcap 文件"""
import os
import struct
import tempfile

out_dir = os.path.join(tempfile.gettempdir(), "pcap_analyzer_test")
os.makedirs(out_dir, exist_ok=True)


def make_eth_ipv4_udp(sport, dport, payload):
    """构造 Ethernet/IPv4/UDP 包"""
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\x00\xaa" + b"\x08\x00"
    udp_len = 8 + 20 + len(payload)
    ver_ihl = (4 << 4) | 5
    ident = 0x1234
    flags_frag = 0x4000
    ttl = 64
    proto = 17
    ip_src = bytes(int(x) for x in "192.168.1.10".split("."))
    ip_dst = bytes(int(x) for x in "10.0.0.1".split("."))
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            ver_ihl, 0, udp_len, ident, flags_frag,
                            ttl, proto, 0, ip_src, ip_dst)
    ip_header = ip_header[:10] + b"\x00\x00" + ip_header[12:]
    udp_header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return eth + ip_header + udp_header + payload


def make_eth_ipv4_tcp(sport, dport, payload):
    """构造 Ethernet/IPv4/TCP 包"""
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\x00\xaa" + b"\x08\x00"
    tcp_len = 20 + 20 + len(payload)
    ver_ihl = (4 << 4) | 5
    ident = 0x1234
    flags_frag = 0x4000
    ttl = 64
    proto = 6
    ip_src = bytes(int(x) for x in "192.168.1.10".split("."))
    ip_dst = bytes(int(x) for x in "10.0.0.1".split("."))
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            ver_ihl, 0, tcp_len, ident, flags_frag,
                            ttl, proto, 0, ip_src, ip_dst)
    ip_header = ip_header[:10] + b"\x00\x00" + ip_header[12:]
    tcp_header = struct.pack("!HHIIB",
                             sport, dport, 1000, 0,
                             ((5 << 4) | 0x18))
    tcp_header += struct.pack("!HHH", 65535, 0, 0)
    return eth + ip_header + tcp_header + payload


def make_eth_ipv4_icmp(payload):
    """构造 Ethernet/IPv4/ICMP 包"""
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\x00\xaa" + b"\x08\x00"
    icmp_len = 20 + len(payload)
    ver_ihl = (4 << 4) | 5
    ident = 0x1234
    flags_frag = 0x4000
    ttl = 64
    proto = 1
    ip_src = bytes(int(x) for x in "192.168.1.10".split("."))
    ip_dst = bytes(int(x) for x in "10.0.0.1".split("."))
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            ver_ihl, 0, icmp_len, ident, flags_frag,
                            ttl, proto, 0, ip_src, ip_dst)
    ip_header = ip_header[:10] + b"\x00\x00" + ip_header[12:]
    return eth + ip_header + payload


def write_pcap(path, packets):
    """写入 pcap 文件"""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts_sec, ts_frac, data in packets:
            f.write(struct.pack("<IIII", ts_sec, ts_frac, len(data), len(data)))
            f.write(data)


frames = []
sec = 1700000000

# ========== 1. DNS Query (UDP 53) ==========
dns_query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
dns_query += b"\x07example\x03com\x00"  # 域名 example.com
dns_query += struct.pack("!HH", 1, 1)   # A 记录, IN 类
frames.append((sec, 0, make_eth_ipv4_udp(52480, 53, dns_query)))
sec += 1

# ========== 2. DNS Response (UDP 53) ==========
dns_resp = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)  # QR=1, NOERROR
dns_resp += b"\x07example\x03com\x00"  # question section domain
dns_resp += struct.pack("!HH", 1, 1)   # A 记录, IN 类
dns_resp += b"\xc0\x0c"  # 回答段域名压缩指针 -> offset 12
dns_resp += struct.pack("!HHIH", 1, 1, 300, 4)  # A 记录, TTL=300, RDLEN=4
dns_resp += bytes(int(x) for x in "93.184.216.34".split("."))  # IP
dns_resp += b"\xc0\x0c"  # 第二个回答压缩指针
dns_resp += struct.pack("!HHIH", 5, 1, 300, 13)  # CNAME, RDLEN=13
dns_resp += b"\x07example\x07example\x03com\x00"
frames.append((sec, 0, make_eth_ipv4_udp(53, 52480, dns_resp)))
sec += 1

# ========== 3. DNS Query for AAAA record ==========
dns_query_aaaa = struct.pack("!HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0)
dns_query_aaaa += b"\x07example\x03com\x00"
dns_query_aaaa += struct.pack("!HH", 28, 1)  # AAAA 记录
frames.append((sec, 0, make_eth_ipv4_udp(52481, 53, dns_query_aaaa)))
sec += 1

# ========== 4. DNS Response for MX record ==========
dns_mx = struct.pack("!HHHHHH", 0xABCD, 0x8180, 1, 1, 0, 0)
dns_mx += b"\x07example\x03com\x00"
dns_mx += struct.pack("!HHIH", 15, 1, 3600, 6)  # MX, RDLEN=6
dns_mx += struct.pack("!H", 10)  # priority
dns_mx += b"\x04mail\x03com\x00"
frames.append((sec, 0, make_eth_ipv4_udp(53, 52481, dns_mx)))
sec += 1

# ========== 5. HTTP GET Request (TCP 80) ==========
http_get = (
    "GET /index.html HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "User-Agent: Mozilla/5.0 (TestBrowser/1.0)\r\n"
    "Accept: text/html,application/xhtml+xml\r\n"
    "Accept-Language: en-US,en;q=0.5\r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Connection: keep-alive\r\n"
    "Cookie: session_id=abc123\r\n"
    "Referer: http://www.example.com/start\r\n"
    "Cache-Control: no-cache\r\n"
    "\r\n"
)
frames.append((sec, 0, make_eth_ipv4_tcp(49200, 80, http_get.encode("ascii"))))
sec += 1

# ========== 6. HTTP 200 OK Response (TCP 80) ==========
http_body = (
    '<!DOCTYPE html><html><head><title>Welcome Page</title></head>'
    '<body><h1>Hello World</h1>'
    '<a href="http://example.com/page1">Page 1</a>'
    '<a href="http://example.com/page2">Page 2</a>'
    '<a href="http://example.com/page3">Page 3</a>'
    '<img src="http://example.com/logo.png">'
    '</body></html>'
)
http_200 = (
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.24.0\r\n"
    "Date: Mon, 15 Jan 2024 12:00:00 GMT\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Content-Length: " + str(len(http_body)) + "\r\n"
    "Connection: keep-alive\r\n"
    "Set-Cookie: session_id=abc123; Path=/; HttpOnly\r\n"
    "ETag: \"3d6-60c6c7d8e5b40\"\r\n"
    "Cache-Control: max-age=3600\r\n"
    "\r\n"
)
frames.append((sec, 0, make_eth_ipv4_tcp(80, 49200,
              (http_200 + http_body).encode("ascii"))))
sec += 1

# ========== 7. HTTP POST Request (TCP 8080) ==========
http_post_body = '{"user":"admin","action":"login","password":"***"}'
http_post = (
    "POST /api/v1/auth HTTP/1.1\r\n"
    "Host: api.example.com:8080\r\n"
    "User-Agent: CustomClient/2.0\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: " + str(len(http_post_body)) + "\r\n"
    "Accept: application/json\r\n"
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9\r\n"
    "\r\n"
    + http_post_body
)
frames.append((sec, 0, make_eth_ipv4_tcp(49201, 8080, http_post.encode("ascii"))))
sec += 1

# ========== 8. HTTP 200 JSON Response (TCP 8080) ==========
json_body = (
    '{"status":"ok","token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ",'
    '"expires_in":3600,"user_id":12345,"role":"admin"}'
)
json_resp = (
    "HTTP/1.1 200 OK\r\n"
    "Server: gunicorn/21.2.0\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: " + str(len(json_body)) + "\r\n"
    "X-Request-Id: req-abc-123\r\n"
    "X-Frame-Options: DENY\r\n"
    "\r\n"
    + json_body
)
frames.append((sec, 0, make_eth_ipv4_tcp(8080, 49201, json_resp.encode("ascii"))))
sec += 1

# ========== 9. HTTP Redirect (302) ==========
redirect_resp = (
    "HTTP/1.1 302 Found\r\n"
    "Location: https://secure.example.com/login\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)
frames.append((sec, 0, make_eth_ipv4_tcp(80, 49202, redirect_resp.encode("ascii"))))
sec += 1

# ========== 10. HTTP 404 Response ==========
error_body = '<html><head><title>404 Not Found</title></head><body><h1>Page Not Found</h1></body></html>'
http_404 = (
    "HTTP/1.1 404 Not Found\r\n"
    "Server: nginx/1.24.0\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Content-Length: " + str(len(error_body)) + "\r\n"
    "X-Error-Code: 404\r\n"
    "\r\n"
    + error_body
)
frames.append((sec, 0, make_eth_ipv4_tcp(80, 49203, http_404.encode("ascii"))))
sec += 1

# ========== 11. RTP Packet (port 5004) ==========
rtp_data = struct.pack("!BBHI", (2 << 6) | 0, 0x64, 1000, 500000)
rtp_data += struct.pack("!I", 0x12345678)  # SSRC
rtp_data += b"\x00" * 4  # 额外的 payload
frames.append((sec, 0, make_eth_ipv4_udp(5004, 5004, rtp_data)))
sec += 1

# ========== 12. RTP Packet with M bit (port 5004) ==========
rtp_m_data = struct.pack("!BBHI", (2 << 6) | 0x80, 96, 1001, 500100)
rtp_m_data += struct.pack("!I", 0x12345678)  # SSRC
rtp_m_data += b"\x00" * 8
frames.append((sec, 0, make_eth_ipv4_udp(5004, 5004, rtp_m_data)))
sec += 1

# ========== 13. RTCP Sender Report (port 5005) ==========
rtcp_sr = struct.pack("!B", 0x80)  # version=2
rtcp_sr += b"\xc0"  # type=SR (192), count=0
rtcp_sr += struct.pack("!H", 6)  # length=6 (24 bytes payload)
rtcp_sr += struct.pack("!I", 0x12345678)  # SSRC
rtcp_sr += struct.pack("!I", 0x00000001)  # NTP high
rtcp_sr += struct.pack("!I", 0x10000000)  # NTP low
rtcp_sr += struct.pack("!I", 500000)  # RTP timestamp
rtcp_sr += struct.pack("!I", 100)  # sender packet count
rtcp_sr += struct.pack("!I", 2000)  # sender octet count
frames.append((sec, 0, make_eth_ipv4_udp(5005, 5005, rtcp_sr)))
sec += 1

# ========== 14. RTCP RR (Receiver Report) ==========
rtcp_rr = struct.pack("!B", 0x80)  # version=2
rtcp_rr += b"\xc1"  # type=RR (193), count=1
rtcp_rr += struct.pack("!H", 10)  # length=10 (40 bytes payload)
rtcp_rr += struct.pack("!I", 0x12345678)  # SSRC
rtcp_rr += struct.pack("!I", 0x12345679)  # Source 1
rtcp_rr += struct.pack("!H", 0)  # fraction lost
rtcp_rr += struct.pack("!I", 0x000a0064)  # extended high
rtcp_rr += struct.pack("!I", 500050)  # jitter
rtcp_rr += struct.pack("!I", 1001)  # LSR
rtcp_rr += struct.pack("!I", 0x00010000)  # DLSR
frames.append((sec, 0, make_eth_ipv4_udp(5005, 5005, rtcp_rr)))
sec += 1

# ========== 15. RTCP BYE ==========
rtcp_bye = struct.pack("!B", 0x80)  # version=2
rtcp_bye += b"\xc3"  # type=BYE (195), count=1
rtcp_bye += struct.pack("!H", 4)  # length=4 (16 bytes payload)
rtcp_bye += struct.pack("!I", 0x12345678)  # SSRC
rtcp_bye += b"\x07Goodbye!"
frames.append((sec, 0, make_eth_ipv4_udp(5005, 5005, rtcp_bye)))
sec += 1

# ========== 16. RTP with Header Extension ==========
rtp_ext = struct.pack("!BBHI", (2 << 6) | 0, 96, 1002, 500200)
rtp_ext += struct.pack("!I", 0x12345678)  # SSRC
# one RTP extension header
rtp_ext += b"\x01\x01"  # ID=1, length=1 (4 bytes payload)
rtp_ext += struct.pack("!I", 0xDEADBEEF)  # extension payload
frames.append((sec, 0, make_eth_ipv4_udp(5004, 5004, rtp_ext)))
sec += 1

# ========== 17. ICMP Echo Request ==========
icmp_ping = b"\x08\x00\x00\x00\x00\x01\x00\x01" + b"\x12\x34\x56\x78" + b"\x00" * 56
frames.append((sec, 0, make_eth_ipv4_icmp(icmp_ping)))
sec += 1

# ========== 18. ICMP Echo Reply ==========
icmp_reply = b"\x00\x00\x00\x00\x00\x01\x00\x01" + b"\x12\x34\x56\x78" + b"\x00" * 56
frames.append((sec, 0, make_eth_ipv4_icmp(icmp_reply)))
sec += 1


pcap_path = os.path.join(out_dir, "dns_http_rtcp_test.pcap")
write_pcap(pcap_path, frames)
print(f"Wrote {len(frames)} packets to {pcap_path}")
# 预期:
#   0: DNS Query for example.com A
#   1: DNS Response (A + CNAME answers)
#   2: DNS Query for AAAA
#   3: DNS Response with MX
#   4: HTTP GET Request
#   5: HTTP 200 OK (HTML body)
#   6: HTTP POST Request (JSON body)
#   7: HTTP 200 OK (JSON response)
#   8: HTTP 302 Redirect
#   9: HTTP 404
#   10-12: RTP (seq=1000/1001, PT=0/96, SSRC)
#   13: RTCP SR (Sender Report)
#   14: RTCP RR (Receiver Report)
#   15: RTCP BYE
#   16: RTP with Extension
#   17: ICMP Echo Request
#   18: ICMP Echo Reply
