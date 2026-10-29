# -*- coding: utf-8 -*-
"""SIP over TCP 粘包/分帧处理 + SDP 体分析测试用例"""
import os
import struct
import tempfile

out_dir = os.path.join(tempfile.gettempdir(), "pcap_analyzer_test")
os.makedirs(out_dir, exist_ok=True)


def make_eth_ipv4_tcp(sport, dport, payload):
    """构造 Ethernet/IPv4/TCP 包(raw bytes)"""
    eth = b"\x00\x11\x22\x33\x44\x55"
    eth += b"\x66\x77\x88\x99\x00\xaa"
    eth += b"\x08\x00"

    seq = 1000
    ack = 0
    data_offset = 5
    flags = 0x18
    win = 65535
    csum = 0
    urg = 0
    total_len = 20 + 20 + len(payload)
    ver_ihl = (4 << 4) | 5
    dscp_ecn = 0
    ident = 0x1234
    flags_frag = 0x4000
    ttl = 64
    proto = 6
    ip_src = bytes(int(x) for x in "192.168.1.10".split("."))
    ip_dst = bytes(int(x) for x in "10.0.0.1".split("."))

    ip_header = struct.pack("!BBHHHBBH4s4s",
                            ver_ihl, dscp_ecn, total_len,
                            ident, flags_frag,
                            ttl, proto, csum,
                            ip_src, ip_dst)
    ip_header = ip_header[:10] + b"\x00\x00" + ip_header[12:]

    tcp_header = struct.pack("!HHIIHHHH",
                             sport, dport, seq, ack,
                             (data_offset << 4) | flags,
                             win, csum, urg)

    return eth + ip_header + tcp_header + payload


def make_eth_ipv4_udp(sport, dport, payload):
    """构造 Ethernet/IPv4/UDP 包"""
    eth = b"\x00\x11\x22\x33\x44\x55"
    eth += b"\x66\x77\x88\x99\x00\xaa"
    eth += b"\x08\x00"

    total_len = 8 + 20 + len(payload)
    ver_ihl = (4 << 4) | 5
    dscp_ecn = 0
    ident = 0x1234
    flags_frag = 0x4000
    ttl = 64
    proto = 17
    csum = 0
    ip_src = bytes(int(x) for x in "192.168.1.10".split("."))
    ip_dst = bytes(int(x) for x in "10.0.0.1".split("."))

    ip_header = struct.pack("!BBHHHBBH4s4s",
                            ver_ihl, dscp_ecn, total_len,
                            ident, flags_frag,
                            ttl, proto, csum,
                            ip_src, ip_dst)
    ip_header = ip_header[:10] + b"\x00\x00" + ip_header[12:]

    udp_header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)

    return eth + ip_header + udp_header + payload


def write_pcap(path, packets):
    """手动写入 pcap 文件"""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII",
                            0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts_sec, ts_frac, data in packets:
            f.write(struct.pack("<IIII", ts_sec, ts_frac, len(data), len(data)))
            f.write(data)


frames = []
sec = 1700000000


# ========== 1. SIP over UDP + SDP 体 ==========
sip_invite_udp = (
    "INVITE sip:bob@10.0.0.1 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK.ud1\r\n"
    "From: <sip:alice@192.168.1.10>;tag=u1\r\n"
    "To: <sip:bob@10.0.0.1>\r\n"
    "Call-ID: call-udp@192.168.1.10\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:alice@192.168.1.10>\r\n"
    "Content-Length: 198\r\n"
    "\r\n"
    "v=0\r\n"
    "o=alice 1 1 IN IP4 192.168.1.10\r\n"
    "s=-\r\n"
    "c=IN IP4 192.168.1.10\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 0 8 96 97 98 99 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:96 telephone-event/8000\r\n"
    "a=fmtp:96 0-15\r\n"
    "m=video 51234 RTP/AVP 34\r\n"
    "a=rtpmap:34 H263-1998/90000\r\n"
)
frames.append((sec, 0, make_eth_ipv4_udp(5060, 5060, sip_invite_udp.encode("ascii"))))
sec += 1

# ========== 2. SIP over TCP 粘包：两条消息在同一 TCP 包 ==========
sip_register = (
    "REGISTER sip:sip.server.com SIP/2.0\r\n"
    "Via: SIP/2.0/TCP 192.168.1.10:5060;branch=z9hG4bK.tc1\r\n"
    "From: <sip:alice@192.168.1.10>;tag=t1\r\n"
    "To: <sip:alice@192.168.1.10>\r\n"
    "Call-ID: call-tcp-reg@192.168.1.10\r\n"
    "CSeq: 1 REGISTER\r\n"
    "Contact: <sip:alice@192.168.1.10;transport=tcp>\r\n"
    "Expires: 3600\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)
sip_options = (
    "OPTIONS sip:monitor@10.0.0.5 SIP/2.0\r\n"
    "Via: SIP/2.0/TCP 192.168.1.10:5060;branch=z9hG4bK.tc2\r\n"
    "From: <sip:admin@192.168.1.10>\r\n"
    "To: <sip:monitor@10.0.0.5>\r\n"
    "Call-ID: call-tcp-opt@192.168.1.10\r\n"
    "CSeq: 1 OPTIONS\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)
# 两条消息粘在一起
frames.append((sec, 0, make_eth_ipv4_tcp(5060, 5060,
                                          sip_register.encode("ascii") +
                                          sip_options.encode("ascii"))))
sec += 1

# ========== 3. SIP over TCP 分帧：200 OK 被拆到两个包 ==========
sip_200_part1 = (
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/TCP 192.168.1.10:5060;branch=z9hG4bK.tc3\r\n"
    "From: <sip:alice@192.168.1.10>;tag=t2\r\n"
    "To: <sip:bob@10.0.0.1>;tag=t2-ok\r\n"
    "Call-ID: call-tcp-ack@192.168.1.10\r\n"
    "CSeq: 1 ACK\r\n"
    "Contact: <sip:bob@10.0.0.1>\r\n"
    "Content-Length: 158\r\n"
    "\r\n"
)
sip_200_sdp = (
    "v=0\r\n"
    "o=bob 3 3 IN IP4 10.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 60000 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtcp:60001 IN IP4 10.0.0.1\r\n"
    "m=video 60002 RTP/AVP 34\r\n"
    "a=rtpmap:34 H263-1998/90000\r\n"
    "a=fmtp:34 profile-level-id=10\r\n"
)
frames.append((sec, 0, make_eth_ipv4_tcp(5060, 5060, sip_200_part1.encode("ascii"))))
frames.append((sec + 1, 0, make_eth_ipv4_tcp(5060, 5060, sip_200_sdp.encode("ascii"))))
sec += 2

# ========== 4. 正常 UDP DNS 包 ==========
frames.append((sec, 0, make_eth_ipv4_udp(40000, 53, b"\x12\x34\x01\x00\x00\x01\x00\x00")))


pcap_path = os.path.join(out_dir, "sip_tcp_test.pcap")
write_pcap(pcap_path, frames)
print(f"Wrote {len(frames)} packets to {pcap_path}")
# 预期: 6 个包
#   - 1: SIP INVITE (UDP, 带 SDP body)
#   - 2: REGISTER + OPTIONS 粘包 (TCP)
#   - 3: 200 OK 头 (TCP, 分帧 part 1)
#   - 4: 200 OK SDP (TCP, 分帧 part 2)
#   - 5: DNS
