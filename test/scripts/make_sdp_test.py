# -*- coding: utf-8 -*-
"""生成带完整 SDP 体的测试 pcap 文件"""
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
    csum = 0
    ip_src = bytes(int(x) for x in "192.168.1.10".split("."))
    ip_dst = bytes(int(x) for x in "10.0.0.1".split("."))

    ip_header = struct.pack("!BBHHHBBH4s4s",
                            ver_ihl, 0, udp_len, ident, flags_frag,
                            ttl, proto, csum, ip_src, ip_dst)
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
    csum = 0
    ip_src = bytes(int(x) for x in "192.168.1.10".split("."))
    ip_dst = bytes(int(x) for x in "10.0.0.1".split("."))

    ip_header = struct.pack("!BBHHHBBH4s4s",
                            ver_ihl, 0, tcp_len, ident, flags_frag,
                            ttl, proto, csum, ip_src, ip_dst)
    ip_header = ip_header[:10] + b"\x00\x00" + ip_header[12:]

    tcp_header = struct.pack("!HHIIH",
                             sport, dport, 1000, 0,
                             ((5 << 4) | 0x18))
    tcp_header += struct.pack("!HHH", 65535, 0, 0)

    return eth + ip_header + tcp_header + payload


def write_pcap(path, packets):
    """写入 pcap 文件"""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts_sec, ts_frac, data in packets:
            f.write(struct.pack("<IIII", ts_sec, ts_frac, len(data), len(data)))
            f.write(data)


frames = []
sec = 1700000000

# ========== 1. SIP INVITE with SDP (SIP over UDP) ==========
invite_sdp = (
    "INVITE sip:bob@10.0.0.1 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK.sdp1\r\n"
    "From: <sip:alice@192.168.1.10>;tag=u1\r\n"
    "To: <sip:bob@10.0.0.1>\r\n"
    "Call-ID: sdp-test-001@192.168.1.10\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:alice@192.168.1.10>\r\n"
    "Content-Length: 412\r\n"
    "\r\n"
    "v=0\r\n"
    "o=alice 45678 1 IN IP4 192.168.1.10\r\n"
    "s=Pedia Call\r\n"
    "c=IN IP4 192.168.1.10\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 0 8 96 97 98 99 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:96 telephone-event/8000\r\n"
    "a=fmtp:96 0-15\r\n"
    "a=rtpmap:97 iLBC/8000\r\n"
    "a=rtpmap:98 Speex/16000\r\n"
    "a=rtpmap:99 iSAC/16000\r\n"
    "a=rtpmap:101 CN/16000\r\n"
    "a=rtcp:49171 IN IP4 192.168.1.10\r\n"
    "a=sendrecv\r\n"
    "m=video 51234 RTP/AVP 34 96 97 98 99 100 101 102 103\r\n"
    "a=rtpmap:34 H263-1998/90000\r\n"
    "a=rtpmap:96 VP8/90000\r\n"
    "a=fmtp:96 max-br=3000;min-br=2000\r\n"
    "a=rtpmap:97 H264/90000\r\n"
    "a=fmtp:97 profile-level-id=42801e;max-br=2000;max-mbps=1638400\r\n"
    "a=rtpmap:98 H264/90000\r\n"
    "a=fmtp:98 profile-level-id=64081e;max-br=800;max-mbps=1638400\r\n"
    "a=rtpmap:99 H264/90000\r\n"
    "a=fmtp:99 profile-level-id=4d001f;max-br=4000;max-mbps=1638400\r\n"
    "a=rtpmap:100 H264/90000\r\n"
    "a=fmtp:100 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f\r\n"
    "a=rtpmap:101 H264/90000\r\n"
    "a=fmtp:101 packetization-mode=0;profile-level-id=64001f\r\n"
    "a=rtpmap:102 H264/90000\r\n"
    "a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f\r\n"
    "a=rtcp:51235 IN IP4 192.168.1.10\r\n"
    "a=sendrecv\r\n"
)
frames.append((sec, 0, make_eth_ipv4_udp(5060, 5060, invite_sdp.encode("ascii"))))
sec += 1

# ========== 2. SIP 200 OK with SDP answer (SIP over UDP) ==========
answer_sdp = (
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK.sdp1\r\n"
    "From: <sip:alice@192.168.1.10>;tag=u1\r\n"
    "To: <sip:bob@10.0.0.1>;tag=bob-ok\r\n"
    "Call-ID: sdp-test-001@192.168.1.10\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:bob@10.0.0.1>\r\n"
    "Content-Length: 356\r\n"
    "\r\n"
    "v=0\r\n"
    "o=bob 87654 1 IN IP4 10.0.0.1\r\n"
    "s=Pedia Call\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 60000 RTP/AVP 0 8 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:101 CN/16000\r\n"
    "a=rtcp:60001 IN IP4 10.0.0.1\r\n"
    "a=sendrecv\r\n"
    "m=video 61000 RTP/AVP 34 97 98\r\n"
    "a=rtpmap:34 H263-1998/90000\r\n"
    "a=rtpmap:97 H264/90000\r\n"
    "a=fmtp:97 profile-level-id=42801e;max-br=2000\r\n"
    "a=rtpmap:98 H264/90000\r\n"
    "a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f\r\n"
    "a=rtcp:61001 IN IP4 10.0.0.1\r\n"
    "a=sendrecv\r\n"
)
frames.append((sec, 0, make_eth_ipv4_udp(5060, 5060, answer_sdp.encode("ascii"))))
sec += 1

# ========== 3. SIP BYE (no SDP body) ==========
bye = (
    "BYE sip:bob@10.0.0.1 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK.bye1\r\n"
    "From: <sip:alice@192.168.1.10>;tag=u1\r\n"
    "To: <sip:bob@10.0.0.1>;tag=bob-ok\r\n"
    "Call-ID: sdp-test-001@192.168.1.10\r\n"
    "CSeq: 2 BYE\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)
frames.append((sec, 0, make_eth_ipv4_udp(5060, 5060, bye.encode("ascii"))))
sec += 1

# ========== 4. SIP INVITE with SDP (SIP over TCP) ==========
invite_tcp_sdp = (
    "INVITE sip:bob@10.0.0.1 SIP/2.0\r\n"
    "Via: SIP/2.0/TCP 192.168.1.10:5060;branch=z9hG4bK.sdp2\r\n"
    "From: <sip:alice@192.168.1.10>;tag=t1\r\n"
    "To: <sip:bob@10.0.0.1>\r\n"
    "Call-ID: sdp-test-002@192.168.1.10\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:alice@192.168.1.10;transport=tcp>\r\n"
    "Content-Length: 263\r\n"
    "\r\n"
    "v=0\r\n"
    "o=alice 99999 1 IN IP4 192.168.1.10\r\n"
    "s=Video Only\r\n"
    "c=IN IP4 192.168.1.10\r\n"
    "t=0 0\r\n"
    "m=video 70000 RTP/AVP 96 97 98\r\n"
    "a=rtpmap:96 VP8/90000\r\n"
    "a=rtpmap:97 H264/90000\r\n"
    "a=fmtp:97 profile-level-id=42801f;max-fs=12288;max-br=3000\r\n"
    "a=rtpmap:98 H264/90000\r\n"
    "a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f\r\n"
    "a=rtcp:70001 IN IP4 192.168.1.10\r\n"
    "a=sendrecv\r\n"
)
frames.append((sec, 0, make_eth_ipv4_tcp(5060, 5060, invite_tcp_sdp.encode("ascii"))))
sec += 1

# ========== 5. SIP 200 OK with SDP (SIP over TCP) ==========
answer_tcp_sdp = (
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/TCP 192.168.1.10:5060;branch=z9hG4bK.sdp2\r\n"
    "From: <sip:alice@192.168.1.10>;tag=t1\r\n"
    "To: <sip:bob@10.0.0.1>;tag=bob-ok2\r\n"
    "Call-ID: sdp-test-002@192.168.1.10\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:bob@10.0.0.1;transport=tcp>\r\n"
    "Content-Length: 191\r\n"
    "\r\n"
    "v=0\r\n"
    "o=bob 12345 1 IN IP4 10.0.0.1\r\n"
    "s=Video Only\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=video 80000 RTP/AVP 96 97\r\n"
    "a=rtpmap:96 VP8/90000\r\n"
    "a=rtpmap:97 H264/90000\r\n"
    "a=fmtp:97 profile-level-id=42801e;max-br=1500\r\n"
    "a=rtcp:80001 IN IP4 10.0.0.1\r\n"
    "a=sendrecv\r\n"
)
frames.append((sec, 0, make_eth_ipv4_tcp(5060, 5060, answer_tcp_sdp.encode("ascii"))))
sec += 1

# ========== 6. Normal DNS (non-SIP, no SDP) ==========
frames.append((sec, 0, make_eth_ipv4_udp(40000, 53, b"\x12\x34\x01\x00\x00\x01\x00\x00")))


pcap_path = os.path.join(out_dir, "sdp_analysis_test.pcap")
write_pcap(pcap_path, frames)
print(f"Wrote {len(frames)} packets to {pcap_path}")
# 预期:
#   1: SIP INVITE (UDP, SDP with audio+video, many codecs)
#   2: SIP 200 OK (UDP, SDP answer with audio+video, fewer codecs)
#   3: SIP BYE (UDP, no SDP body)
#   4: SIP INVITE (TCP, SDP with video-only)
#   5: SIP 200 OK (TCP, SDP answer with video-only)
#   6: DNS (no SDP)
