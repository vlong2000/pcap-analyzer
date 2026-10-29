# -*- coding: utf-8 -*-
"""生成包含各种 L7 协议流量的测试 pcap 文件"""
import struct
import os
import tempfile

out_dir = os.path.join(tempfile.gettempdir(), "pcap_analyzer_test")
os.makedirs(out_dir, exist_ok=True)

SEC = 1700000000


def make_eth_ipv4_udp(sport, dport, payload):
    """构造 Ethernet/IPv4/UDP 帧"""
    eth = b"\x00\x11\x22\x33\x44\x55"
    eth += b"\x66\x77\x88\x99\x00\xaa"
    eth += b"\x08\x00"
    total_len = 20 + 8 + len(payload)
    ip_header = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 0x1234, 0x4000, 64, 17, 0,
        bytes(int(x) for x in "192.168.1.10".split(".")),
        bytes(int(x) for x in "10.0.0.1".split(".")))
    udp_len = 8 + len(payload)
    udp_header = struct.pack("!HHHH", sport, dport, udp_len, 0)
    return eth + ip_header + udp_header + payload


def make_eth_ipv4_tcp(sport, dport, payload, flags=0x02):
    """构造 Ethernet/IPv4/TCP 帧"""
    eth = b"\x00\x11\x22\x33\x44\x55"
    eth += b"\x66\x77\x88\x99\x00\xaa"
    eth += b"\x08\x00"
    total_len = 20 + 20 + len(payload)
    ip_header = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 0x1234, 0x4000, 64, 6, 0,
        bytes(int(x) for x in "192.168.1.10".split(".")),
        bytes(int(x) for x in "10.0.0.1".split(".")))
    # TCP header: sport, dport, seq, ack, data_offset(5<<12)+flags, window, 0, urgent
    tcp_header = struct.pack("!HHIIHHHH", sport, dport, 1000, 2000, (5 << 12) | flags, 65535, 0, 0)
    return eth + ip_header + tcp_header + payload


# ===== L7 端口匹配（UDP）=====

# DNS 消息构造（标准 12 字节头部：id + flags + qdcount/ancount/nscount/arcount）
def dns_msg(txn_id, flags, qname, qtype):
    hdr = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)
    return hdr + qname + struct.pack("!HH", qtype, 1)


dns_qname = b"\x03www\x07example\x03com\x00"

# DNS query over UDP (port 53)
dns_payload = dns_msg(0x1234, 0x0100, dns_qname, 1)  # QR=0, RD=1
pkts = []
pkts.append((SEC, make_eth_ipv4_udp(55000, 53, dns_payload)))

# DNS response over UDP (port 53, QR=1)
dns_resp = dns_msg(0x1234, 0x8180, dns_qname, 1)  # QR=1, RD=1, RA=1
pkts.append((SEC + 1, make_eth_ipv4_udp(53, 55000, dns_resp)))

# SIP over UDP (port 5060)
sip_payload = b"INVITE sip:bob@10.0.0.1 SIP/2.0\r\n" \
              b"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" \
              b"From: <sip:alice@192.168.1.10>\r\n" \
              b"To: <sip:bob@10.0.0.1>\r\n" \
              b"Call-ID: test@sip\r\n" \
              b"CSeq: 1 INVITE\r\n" \
              b"Content-Length: 0\r\n\r\n"
pkts.append((SEC + 2, make_eth_ipv4_udp(5060, 5060, sip_payload)))

# NTP over UDP (port 123)
ntp_payload = b"\xe3\x00\x04\xfa" + b"\x00" * 44  # NTP simple packet
pkts.append((SEC + 3, make_eth_ipv4_udp(12345, 123, ntp_payload)))

# STUN over UDP (port 3478)
stun_payload = b"\x00\x01" + b"\x00\x0c" + b"\x21\x12\xa44" + b"\x00" * 8  # STUN binding request
pkts.append((SEC + 4, make_eth_ipv4_udp(50000, 3478, stun_payload)))


# ===== L7 端口匹配（TCP）=====

# HTTP over TCP (port 80)
http_get = b"GET /index.html HTTP/1.1\r\n" \
           b"Host: www.example.com\r\n" \
           b"User-Agent: Test/1.0\r\n" \
           b"Accept: */*\r\n" \
           b"\r\n"
pkts.append((SEC + 5, make_eth_ipv4_tcp(45000, 80, http_get)))

# SSH over TCP (port 22)
ssh_payload = b"SSH-2.0-Python\r\n"
pkts.append((SEC + 6, make_eth_ipv4_tcp(50100, 22, ssh_payload, flags=0x12)))  # SYN+ACK

# MySQL over TCP (port 3306)
mysql_payload = struct.pack("!I", 0) + b"\fb" + b"\x00\x00" + b"\x00" * 10
pkts.append((SEC + 7, make_eth_ipv4_tcp(50200, 3306, mysql_payload, flags=0x12)))

# SMTP over TCP (port 25)
smtp_payload = b"EHLO mail.example.com\r\n"
pkts.append((SEC + 8, make_eth_ipv4_tcp(50300, 25, smtp_payload, flags=0x12)))

# POST over TCP (8080 端口，HTTP 特征识别)
http_post = b"POST /api/login HTTP/1.1\r\n" \
            b"Host: app.example.com\r\n" \
            b"Content-Type: application/json\r\n" \
            b"Content-Length: 30\r\n\r\n" \
            b'{"username":"test","pass":"123"}'
pkts.append((SEC + 9, make_eth_ipv4_tcp(50400, 8080, http_post)))


# ===== L7 payload 特征识别（非标准端口）=====

# SIP 通过非标准端口识别 (payload 特征)
sip_via_feature = b"ACK sip:alice@10.0.0.5:9999 SIP/2.0\r\n" \
                  b"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" \
                  b"From: <sip:alice@192.168.1.10>\r\n" \
                  b"To: <sip:bob@10.0.0.5:9999>\r\n" \
                  b"Call-ID: feat-test@sip\r\n" \
                  b"CSeq: 2 ACK\r\n\r\n"
pkts.append((SEC + 10, make_eth_ipv4_udp(5060, 9999, sip_via_feature)))

# HTTP 响应通过非标准端口识别 (payload 特征)
http_resp_feature = b"HTTP/1.1 200 OK\r\n" \
                    b"Content-Type: text/html\r\n" \
                    b"Content-Length: 0\r\n\r\n"
pkts.append((SEC + 11, make_eth_ipv4_tcp(8081, 55001, http_resp_feature)))

# SIP 200 OK 响应 (payload 特征)
sip_resp_feature = b"SIP/2.0 200 OK\r\n" \
                   b"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" \
                   b"From: <sip:alice@192.168.1.10>;tag=abc\r\n" \
                   b"To: <sip:bob@10.0.0.1>;tag=xyz\r\n" \
                   b"Call-ID: resp-test@sip\r\n" \
                   b"CSeq: 1 INVITE\r\n\r\n"
pkts.append((SEC + 12, make_eth_ipv4_udp(5060, 5060, sip_resp_feature)))


# ===== L7 payload 特征识别 - TCP DNS 响应 =====
# TCP 上的 DNS 带 2 字节长度前缀（RFC 1035 §4.2.2），其后是完整 DNS 消息
tcp_dns_msg = dns_msg(0x5678, 0x8180, dns_qname, 1)  # QR=1
tcp_dns_resp = struct.pack("!H", len(tcp_dns_msg)) + tcp_dns_msg
pkts.append((SEC + 13, make_eth_ipv4_tcp(55002, 49152, tcp_dns_resp)))


# ===== RTP 测试 =====
# RTP 包（port 5004 端口），V=2
rtp_version = (2 << 6)
rtp_payload = bytes([rtp_version | 0, 0x80]) + struct.pack("!IIII", 0x12345678, 0x87654321, 0xDEADBEEF, 0xCAFEBABE)
pkts.append((SEC + 14, make_eth_ipv4_udp(50000, 5004, rtp_payload)))

# RTCP 包（SR，type=200；奇数端口按 RTCP 处理），V=2
rtcp_rtp_version = (2 << 6)
rtcp_payload = bytes([rtcp_rtp_version | 0x00, 200]) + struct.pack("!I", 0) + b"\x00" * 12
pkts.append((SEC + 15, make_eth_ipv4_udp(50000, 50005, rtcp_payload)))


# ===== write_pcap =====
def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            ts_sec = int(ts)
            ts_frac = int((ts - ts_sec) * 1000000)
            f.write(struct.pack("<IIII", ts_sec, ts_frac, len(data), len(data)))
            f.write(data)

pcap_path = os.path.join(out_dir, "l7_test.pcap")
write_pcap(pcap_path, pkts)
print(f"Wrote {len(pkts)} packets to {pcap_path}")
