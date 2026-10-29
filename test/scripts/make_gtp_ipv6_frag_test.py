# -*- coding: utf-8 -*-
"""生成 GTP-U 内层 IPv6 分片重组的测试 pcap 文件"""
import ipaddress
import os
import struct
import tempfile

out_dir = os.path.join(tempfile.gettempdir(), "pcap_analyzer_test")
os.makedirs(out_dir, exist_ok=True)

SEC = 1700000100
SRC_MAC = b"\x00\x11\x22\x33\x44\x55"
DST_MAC = b"\x66\x77\x88\x99\x00\xaa"
OUTER_SRC = bytes((10, 107, 15, 45))
OUTER_DST = bytes((10, 100, 61, 8))
INNER_SRC = ipaddress.IPv6Address("2a02:9b0:6e:edba:862:3470:4ae0:7c8c").packed
INNER_DST = ipaddress.IPv6Address("2a02:ce0:7:c000::c185").packed


def gtp_frame(teid, inner, ip_id):
    """Ethernet/IPv4/UDP:2152 + GTP-U G-PDU + 内层 IPv6 包"""
    eth = SRC_MAC + DST_MAC + b"\x08\x00"
    gtp = struct.pack("!BBHI", 0x30, 0xFF, 4 + len(inner), teid) + inner
    udp = struct.pack("!HHHH", 2152, 2152, 8 + len(gtp), 0) + gtp
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ip_id, 0, 64, 17, 0,
                     OUTER_SRC, OUTER_DST)
    return eth + ip + udp


def inner_ipv6_frag(nxt, body, frag_off=0, more=False, frag_id=1):
    """内层 IPv6 + 分片头；frag_off 以字节计，内部换算成 8 字节单位"""
    bits = ((frag_off // 8) << 3) | (1 if more else 0)
    frag = bytes((nxt, 0)) + struct.pack("!H", bits) + struct.pack("!I", frag_id)
    payload = frag + body
    return (struct.pack("!IHBB", 0x60000000, len(payload), 44, 64)
            + INNER_SRC + INNER_DST + payload)


def tcp_header(sport, dport, flags=0x18):
    return struct.pack("!HHIIHHHH", sport, dport, 1, 0, (5 << 12) | flags, 65535, 0, 0)


def udp_header(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


pkts = []
base = SEC

# ---- 场景 1：首片带 DestOpts，末片补齐；重组后剥离扩展头，端口可见 ----
dest_opts = bytes((6, 0)) + b"\x00" * 6                       # DestOpts，下一头 TCP
body1 = dest_opts + tcp_header(5555, 443) + b"\x00" * 4       # 8 + 20 + 4 = 32，8 字节对齐
pkts.append((base + 0, gtp_frame(0x00000001,
             inner_ipv6_frag(60, body1, frag_off=0, more=True, frag_id=0x1111), 1)))
pkts.append((base + 1, gtp_frame(0x00000001,
             inner_ipv6_frag(60, b"\xaa" * 4, frag_off=32, more=False, frag_id=0x1111), 2)))

# ---- 场景 2：内层 UDP 两片顺序到达，无扩展头 ----
udp_payload = udp_header(1000, 2000, b"\x00" * 16)            # 8 + 16 = 24
pkts.append((base + 2, gtp_frame(0x00000002,
             inner_ipv6_frag(17, udp_payload[:16], frag_off=0, more=True, frag_id=0x2222), 3)))
pkts.append((base + 3, gtp_frame(0x00000002,
             inner_ipv6_frag(17, udp_payload[16:], frag_off=16, more=False, frag_id=0x2222), 4)))

# ---- 场景 3：末片先到、首片后补；补齐首片时立即完成重组 ----
pkts.append((base + 4, gtp_frame(0x00000003,
             inner_ipv6_frag(17, udp_payload[16:], frag_off=16, more=False, frag_id=0x3333), 5)))
pkts.append((base + 5, gtp_frame(0x00000003,
             inner_ipv6_frag(17, udp_payload[:16], frag_off=0, more=True, frag_id=0x3333), 6)))

# ---- 场景 4：缺中片（三片只给首片与末片，off=8 缺失） ----
frag_body = udp_header(3000, 4000)                            # 8 字节，分片对齐
pkts.append((base + 6, gtp_frame(0x00000004,
             inner_ipv6_frag(17, frag_body, frag_off=0, more=True, frag_id=0x4444), 7)))
pkts.append((base + 7, gtp_frame(0x00000004,
             inner_ipv6_frag(17, frag_body, frag_off=16, more=False, frag_id=0x4444), 8)))

# ---- 场景 5：不同 frag_id 交织，互不拼接 ----
pkts.append((base + 8, gtp_frame(0x00000005,
             inner_ipv6_frag(17, udp_header(5050, 6060), frag_off=0, more=True, frag_id=0x5555), 9)))
pkts.append((base + 9, gtp_frame(0x00000005,
             inner_ipv6_frag(17, frag_body, frag_off=8, more=False, frag_id=0x6666), 10)))

# ---- 场景 6：同 frag_id 被新报文复用，首片内容不同则重建 ----
pkts.append((base + 10, gtp_frame(0x00000006,
             inner_ipv6_frag(17, udp_header(1000, 2000), frag_off=0, more=True, frag_id=0x7777), 11)))
pkts.append((base + 11, gtp_frame(0x00000006,
             inner_ipv6_frag(17, udp_header(7000, 8000), frag_off=0, more=True, frag_id=0x7777), 12)))
pkts.append((base + 12, gtp_frame(0x00000006,
             inner_ipv6_frag(17, frag_body, frag_off=8, more=False, frag_id=0x7777), 13)))

# ---- 场景 7：首片缺失（先到末片），补齐首片后完成 ----
pkts.append((base + 13, gtp_frame(0x00000007,
             inner_ipv6_frag(17, frag_body, frag_off=8, more=False, frag_id=0x8888), 14)))
pkts.append((base + 14, gtp_frame(0x00000007,
             inner_ipv6_frag(17, udp_header(9000, 9100), frag_off=0, more=True, frag_id=0x8888), 15)))


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            ts_sec = int(ts)
            ts_frac = int((ts - ts_sec) * 1000000)
            f.write(struct.pack("<IIII", ts_sec, ts_frac, len(data), len(data)))
            f.write(data)


pcap_path = os.path.join(out_dir, "gtp_ipv6_frag_test.pcap")
write_pcap(pcap_path, pkts)
print(f"Wrote {len(pkts)} packets to {pcap_path}")
