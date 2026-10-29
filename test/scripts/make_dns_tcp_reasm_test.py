# -*- coding: utf-8 -*-
"""生成 DNS over TCP 跨段重组的测试 pcap 文件"""
import os
import struct
import tempfile

out_dir = os.path.join(tempfile.gettempdir(), "pcap_analyzer_test")
os.makedirs(out_dir, exist_ok=True)

SEC = 1700000000
SRC_MAC = b"\x00\x11\x22\x33\x44\x55"
DST_MAC = b"\x66\x77\x88\x99\x00\xaa"


def tcp_frame(sport, dport, seq, payload, flags=0x18, ip_id=0x1234):
    """构造 Ethernet/IPv4/TCP 帧，序号由调用方指定"""
    eth = SRC_MAC + DST_MAC + b"\x08\x00"
    total_len = 20 + 20 + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, ip_id, 0x4000, 64, 6, 0,
        bytes(int(x) for x in "10.0.0.1".split(".")),
        bytes(int(x) for x in "192.168.1.10".split(".")))
    tcp_header = struct.pack("!HHIIHHHH", sport, dport, seq, 0,
                             (5 << 12) | flags, 65535, 0, 0)
    return eth + ip_header + tcp_header + payload


def dns_msg(txn_id, qr=True, qname=b"\x03www\x07example\x03com\x00"):
    flags = 0x8180 if qr else 0x0100
    return struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def prefixed(msg):
    return struct.pack("!H", len(msg)) + msg


pkts = []
base = SEC

# ---- 场景 1：消息切两段顺序到达（R2）----
msg1 = dns_msg(0x1111)
stream1 = prefixed(msg1)
split = 16
pkts.append((base + 0, tcp_frame(53, 20001, 7000, b"", flags=0x02, ip_id=1)))          # SYN
pkts.append((base + 1, tcp_frame(53, 20001, 7001, stream1[:split], ip_id=2)))          # 段 1
pkts.append((base + 2, tcp_frame(53, 20001, 7001 + split, stream1[split:], ip_id=3)))  # 段 2

# ---- 场景 2：乱序到达 + 重传（R4/R6）----
msg2 = dns_msg(0x2222)
stream2 = prefixed(msg2)
split2 = 20
pkts.append((base + 3, tcp_frame(53, 20002, 9001 + split2, stream2[split2:], ip_id=4)))  # 后段先到
pkts.append((base + 4, tcp_frame(53, 20002, 9001, stream2[:split2], ip_id=5)))           # 前段补齐
pkts.append((base + 5, tcp_frame(53, 20002, 9001 + split2, stream2[split2:], ip_id=6)))  # 重传

# ---- 场景 3：同段粘两条消息（R8）----
msg3a = dns_msg(0x3333)
msg3b = dns_msg(0x4444)
pkts.append((base + 6, tcp_frame(53, 20003, 11001, prefixed(msg3a) + prefixed(msg3b), ip_id=7)))

# ---- 场景 4：长度前缀被切开（R10）----
msg4 = dns_msg(0x5555)
stream4 = prefixed(msg4)
pkts.append((base + 7, tcp_frame(53, 20004, 13001, stream4[:1], ip_id=8)))   # 仅 1 字节前缀
pkts.append((base + 8, tcp_frame(53, 20004, 13002, stream4[1:], ip_id=9)))   # 其余

# ---- 场景 5：SYN 重置后重新收完整消息（R12）----
msg5 = dns_msg(0x6666)
stream5 = prefixed(msg5)
pkts.append((base + 9, tcp_frame(53, 20005, 15001, stream5[:10], ip_id=10)))
pkts.append((base + 10, tcp_frame(53, 20005, 18000, b"", flags=0x02, ip_id=11)))  # 新 SYN
pkts.append((base + 11, tcp_frame(53, 20005, 18001, stream5, ip_id=12)))


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            ts_sec = int(ts)
            ts_frac = int((ts - ts_sec) * 1000000)
            f.write(struct.pack("<IIII", ts_sec, ts_frac, len(data), len(data)))
            f.write(data)


pcap_path = os.path.join(out_dir, "dns_tcp_reasm_test.pcap")
write_pcap(pcap_path, pkts)
print(f"Wrote {len(pkts)} packets to {pcap_path}")
