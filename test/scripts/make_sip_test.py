# -*- coding: utf-8 -*-
"""生成包含 SIP 流量的测试 pcap 文件"""
import os
import struct
import tempfile

out_dir = os.path.join(tempfile.gettempdir(), "pcap_analyzer_test")
os.makedirs(out_dir, exist_ok=True)


def make_eth_ipv4_udp(sport, dport, payload):
    """构造 Ethernet/IPv4/UDP 包(raw bytes)"""
    # Ethernet header (14 bytes)
    eth = b"\x00\x11\x22\x33\x44\x55"  # dst MAC
    eth += b"\x66\x77\x88\x99\x00\xaa"  # src MAC
    eth += b"\x08\x00"  # EtherType IPv4

    # IPv4 header (20 bytes, no options)
    total_len = 20 + 8 + len(payload)  # IP + UDP + payload
    ver_ihl = (4 << 4) | 5
    dscp_ecn = 0
    ident = 0x1234
    flags_frag = 0x4000  # Don't Fragment
    ttl = 64
    proto = 17  # UDP

    ip_src = bytes(int(x) for x in "192.168.1.10".split("."))
    ip_dst = bytes(int(x) for x in "10.0.0.1".split("."))

    ip_header = struct.pack("!BBHHHBBH4s4s",
                            ver_ihl, dscp_ecn, total_len,
                            ident, flags_frag,
                            ttl, proto, 0,
                            ip_src, ip_dst)
    # checksum placeholder, fill 0
    ip_header = ip_header[:10] + b"\x00\x00" + ip_header[12:]

    # UDP header (8 bytes)
    udp_len = 8 + len(payload)
    udp_header = struct.pack("!HHHH", sport, dport, udp_len, 0)

    return eth + ip_header + udp_header + payload


def write_pcap(path, packets):
    """手动写入 pcap 文件(不含 scapy 依赖)"""
    endian = "<"
    with open(path, "wb") as f:
        # pcap global header
        f.write(struct.pack(endian + "IHHiIII",
                            0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))  # v2.4, snap=65535, eth=1
        for ts_sec, ts_frac, data in packets:
            f.write(struct.pack(endian + "IIII", ts_sec, ts_frac, len(data), len(data)))
            f.write(data)


frames = []
sec = 1700000000  # base timestamp

# SIP INVITE request
sip_invite = (
    "INVITE sip:bob@10.0.0.1 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK.test1\r\n"
    "From: <sip:alice@192.168.1.10>;tag=alice123\r\n"
    "To: <sip:bob@10.0.0.1>\r\n"
    "Call-ID: call001@192.168.1.10\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:alice@192.168.1.10>\r\n"
    "Content-Length: 143\r\n"
    "\r\n"
    "v=0\r\no=- 1 1 IN IP4 192.168.1.10\r\n"
)
frames.append((sec, 0, make_eth_ipv4_udp(5060, 5060, sip_invite.encode("ascii"))))
sec += 1

# SIP 200 OK response
sip_200 = (
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK.test1\r\n"
    "From: <sip:alice@192.168.1.10>;tag=alice123\r\n"
    "To: <sip:bob@10.0.0.1>;tag=bob456\r\n"
    "Call-ID: call001@192.168.1.10\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:bob@10.0.0.1>\r\n"
    "Content-Length: 143\r\n"
    "\r\n"
    "v=0\r\no=bob 2 2 IN IP4 10.0.0.1\r\n"
)
frames.append((sec, 0, make_eth_ipv4_udp(5060, 5060, sip_200.encode("ascii"))))
sec += 1

# SIP BYE
sip_bye = (
    "BYE sip:bob@10.0.0.1 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK.test2\r\n"
    "From: <sip:alice@192.168.1.10>;tag=alice123\r\n"
    "To: <sip:bob@10.0.0.1>;tag=bob456\r\n"
    "Call-ID: call001@192.168.1.10\r\n"
    "CSeq: 2 BYE\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)
frames.append((sec, 0, make_eth_ipv4_udp(5060, 5060, sip_bye.encode("ascii"))))
sec += 1

# SIP REGISTER
sip_register = (
    "REGISTER sip:sip.server.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK.test3\r\n"
    "From: <sip:alice@192.168.1.10>;tag=alice789\r\n"
    "To: <sip:alice@192.168.1.10>\r\n"
    "Call-ID: call002@192.168.1.10\r\n"
    "CSeq: 1 REGISTER\r\n"
    "Contact: <sip:alice@192.168.1.10;transport=udp>\r\n"
    "Expires: 3600\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)
frames.append((sec, 0, make_eth_ipv4_udp(5060, 5060, sip_register.encode("ascii"))))
sec += 1

# SIP 401 Unauthorized
sip_401 = (
    "SIP/2.0 401 Unauthorized\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK.test3\r\n"
    "From: <sip:alice@192.168.1.10>;tag=alice789\r\n"
    "To: <sip:alice@192.168.1.10>;tag=server001\r\n"
    "Call-ID: call002@192.168.1.10\r\n"
    "CSeq: 1 REGISTER\r\n"
    "WWW-Authenticate: Digest realm=\"sip.server.com\", nonce=\"abc123\"\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)
frames.append((sec, 0, make_eth_ipv4_udp(5060, 5060, sip_401.encode("ascii"))))
sec += 1

# SIP OPTIONS
sip_options = (
    "OPTIONS sip:monitor@10.0.0.5 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK.test4\r\n"
    "From: <sip:admin@192.168.1.10>\r\n"
    "To: <sip:monitor@10.0.0.5>\r\n"
    "Call-ID: call003@192.168.1.10\r\n"
    "CSeq: 1 OPTIONS\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)
frames.append((sec, 0, make_eth_ipv4_udp(5060, 5060, sip_options.encode("ascii"))))
sec += 1

# SIP 487 Request Terminated
sip_487 = (
    "SIP/2.0 487 Request Terminated\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK.test1\r\n"
    "From: <sip:alice@192.168.1.10>;tag=alice123\r\n"
    "To: <sip:bob@10.0.0.1>;tag=bob456\r\n"
    "Call-ID: call001@192.168.1.10\r\n"
    "CSeq: 2 BYE\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)
frames.append((sec, 0, make_eth_ipv4_udp(5060, 5060, sip_487.encode("ascii"))))
sec += 1

# Non-SIP UDP (DNS) for contrast
frames.append((sec, 0, make_eth_ipv4_udp(40000, 53, b"\x12\x34\x01\x00\x00\x01\x00\x00")))

pcap_path = os.path.join(out_dir, "sip_test.pcap")
write_pcap(pcap_path, frames)
print(f"Wrote {len(frames)} packets to {pcap_path}")
