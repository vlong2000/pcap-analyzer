#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pcap_analyzer.py —— PCAP / PCAPNG 抓包文件解析工具

能力概览:
  * 容器格式 : pcap(微秒/纳秒, 大端/小端)、pcapng(多 interface, if_tsresol)
  * 链路层   : Ethernet(含 802.1Q/QinQ)、Linux SLL/SLL2、RAW IP、NULL/LOOP
  * 网络层   : IPv4(含分片)、IPv6(含扩展头链)、ARP
  * 传输层   : TCP(标志位/选项)、UDP、SCTP(chunk 与 PPID 解析)、
               ICMPv4/ICMPv6、IGMP、GRE、ESP/AH、OSPF、VRRP 等
  * 输出     : 汇总统计(协议分布/端口/会话 Top)、逐包列表、JSON

用法示例:
  python pcap_analyzer.py capture.pcap
  python pcap_analyzer.py capture.pcap -v --filter sctp
  python pcap_analyzer.py capture.pcap -v --filter tcp --limit 200
  python pcap_analyzer.py capture.pcap -v --dump both      # 载荷十六进制+字符串
  python pcap_analyzer.py capture.pcapng --json > result.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import struct
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Optional

# --------------------------------------------------------------------------- #
# 常量表
# --------------------------------------------------------------------------- #

# pcap 文件头 magic -> (字节序, 每秒时间戳单位, 格式名)
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000, "pcap (小端, 微秒)"),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000, "pcap (大端, 微秒)"),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000, "pcap (小端, 纳秒)"),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000, "pcap (大端, 纳秒)"),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

LINKTYPE_NAMES = {
    0: "NULL/LOOP",
    1: "EN10MB (Ethernet)",
    101: "RAW (IP)",
    105: "IEEE802_11",
    113: "LINUX_SLL",
    127: "IEEE802_11_RADIOTAP",
    228: "IPV4",
    229: "IPV6",
    276: "LINUX_SLL2",
}

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806
ETH_VLAN = {0x8100, 0x88A8, 0x9100}
ETHERTYPE_NAMES = {
    ETH_IPV4: "IPv4", ETH_IPV6: "IPv6", ETH_ARP: "ARP", 0x8035: "RARP",
    0x8847: "MPLS", 0x8863: "PPPoE-Discovery", 0x8864: "PPPoE-Session",
    0x88CC: "LLDP", 0x888E: "EAPoL",
}

IP_PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP",
    132: "SCTP", 136: "UDPLite",
}

# SCTP chunk 类型 (RFC 4960 / 9260 及常见扩展)
SCTP_CHUNKS = {
    0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK", 4: "HEARTBEAT",
    5: "HEARTBEAT_ACK", 6: "ABORT", 7: "SHUTDOWN", 8: "SHUTDOWN_ACK",
    9: "ERROR", 10: "COOKIE_ECHO", 11: "COOKIE_ACK", 12: "ECNE", 13: "CWR",
    14: "SHUTDOWN_COMPLETE", 15: "AUTH", 64: "I_DATA", 130: "RE_CONFIG",
    132: "PAD", 192: "FORWARD_TSN",
}

# SCTP Payload Protocol Identifier 常见取值 (IANA)
SCTP_PPIDS = {
    0: "Unspecified", 1: "IUA", 2: "M2UA", 3: "M3UA", 4: "SUA", 5: "M2PA",
    7: "ISUP", 8: "H.248", 9: "H.323", 18: "S1AP", 46: "Diameter",
    62: "ASAP", 128: "Padding",
}

# SIP 方法 (RFC 3261)
SIP_METHODS = {"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "MESSAGE",
               "PRACK", "SUBSCRIBE", "NOTIFY", "REFER", "INFO", "OPTIONS",
               "UPDATE", "PUBLISH", "COMMIT"}

# SIP 响应状态码描述 (RFC 3261 + 扩展)
SIP_STATUS = {
    100: "Trying", 180: "Ringing", 181: "CallIsForwarded", 182: "Queued",
    183: "SessionProgress", 199: "EarlyDialogTerminated",
    200: "OK", 202: "Accepted", 204: "NoNotification",
    300: "MultipleChoices", 301: "MovedPermanently", 302: "MovedTemporarily",
    305: "UseProxy", 380: "AlternativeService",
    400: "BadRequest", 401: "Unauthorized", 402: "PaymentRequired",
    403: "Forbidden", 404: "NotFound", 405: "MethodNotAllowed",
    406: "NotAcceptable", 407: "ProxyAuthRequired", 408: "RequestTimeout",
    410: "Gone", 413: "RequestEntityTooLarge", 414: "RequestURITooLong",
    415: "UnsupportedMediaType", 416: "UnsupportedURI", 420: "BadExtension",
    421: "ExtensionRequired", 422: "SessionIntervalTooSmall",
    423: "IntervalTooBrief", 424: "BadLocationInfo", 428: "UseIdentityHeader",
    430: "CallIDNotFound", 433: "AnonymityDisallowed",
    436: "BadIdentityHeader", 437: "UnrecognizedHeader",
    439: "UnsupportsHost", 480: "TemporarilyUnavailable",
    481: "CallLegTransactionDoesNotExist", 482: "LoopDetected",
    483: "TooManyHops", 484: "AddressIncomplete", 485: "Ambiguous",
    486: "BusyHere", 487: "RequestTerminated", 488: "NotAcceptableHere",
    489: "BadEvent", 491: "PendingRequest", 493: "DecryptFailed",
    500: "SIPError", 501: "NotImplemented", 502: "BadGateway",
    503: "ServiceUnavailable", 504: "ServerTimeOut", 505: "VersionUnsupported",
    513: "MessageTooLarge", 580: "PreconditionFailure",
    600: "GlobalBusyHere", 603: "GlobalDecline", 604: "GlobalDoesNotExist",
    606: "GlobalNotAcceptable",
}

TCP_FLAG_BITS = [(0x002, "SYN"), (0x001, "FIN"), (0x004, "RST"), (0x008, "PSH"),
                 (0x010, "ACK"), (0x020, "URG"), (0x040, "ECE"), (0x080, "CWR"),
                 (0x100, "NS")]

ICMP4_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
    8: "Echo Request", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp", 14: "Timestamp Reply",
}
ICMP6_TYPES = {
    1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
    4: "Parameter Problem", 128: "Echo Request", 129: "Echo Reply",
    133: "Router Solicitation", 134: "Router Advertisement",
    135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
    137: "Redirect",
}

# DNS 响应码 (RFC 1035)
DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}

# DNS 查询类型 (RFC 1035)
DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
    41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
    64: "HTTPS", 65: "SVCB",
}

# DNS 类别 (RFC 1035)
DNS_QCLASSES = {1: "IN", 3: "CH", 4: "HS", 255: "ANY"}

# RTP payload type 名称 (RFC 3551 / RFC 6464)
RTP_PAYLOAD_NAMES = {
    0: "PCMU/8000", 3: "GSM", 4: "G723", 10: "LVCM", 11: "LVCM",
    13: "CN", 14: "MPA", 15: "G729", 18: "G729a",
    26: "CN", 29: "PVCP", 31: "H261", 32: "MPV", 33: "MP2T",
    34: "H263", 96: "dynamic", 97: "dynamic", 98: "dynamic",
    99: "dynamic", 100: "dynamic", 101: "dynamic", 102: "dynamic",
    103: "dynamic", 104: "dynamic", 105: "dynamic", 106: "dynamic",
    107: "dynamic", 108: "dynamic", 109: "dynamic", 110: "dynamic",
    111: "dynamic", 112: "dynamic", 113: "dynamic", 114: "dynamic",
    115: "dynamic", 116: "dynamic", 117: "dynamic", 118: "dynamic",
    119: "dynamic", 120: "dynamic", 121: "dynamic", 122: "dynamic",
    123: "dynamic", 124: "dynamic", 125: "dynamic", 126: "dynamic",
    127: "dynamic",
}

# RTCP 包类型 (RFC 3550)
RTCP_TYPES = {
    192: "SR", 193: "RR", 194: "SDES", 195: "BYE", 196: "APP",
    200: "RTPFB", 201: "PSFB", 202: "XR", 207: "RTCPv2",
}

# SIP 方法列表（payload 特征识别用）
SIP_METHODS = {"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "PRACK", "SUBSCRIBE", "NOTIFY", "MESSAGE", "UPDATE"}

# L7 端口 -> 协议名 映射（UDP）
UDP_PORT_MAP = {
    80: "HTTP", 443: "HTTPS", 8080: "HTTP", 8443: "HTTPS",
    53: "DNS",
    5060: "SIP", 5061: "SIPS",
    5004: "RTP", 5005: "RTCP", 8000: "RTP", 8001: "RTCP",
    22: "SSH", 123: "NTP", 3478: "STUN", 3479: "STUN-TURN",
    50040: "RTP", 50041: "RTCP",
    2152: "GTP-U", 2123: "GTP-C", 3386: "GTP'",
    4500: "NAT-T",
}

# GTP 消息类型（GTPv1-C/U）
GTP_MESSAGE_TYPES = {
    0x01: "Echo Request",
    0x02: "Echo Response",
    0x20: "End Marker",
    0xFE: "Error Indication",
    0xFF: "G-PDU",
}

# 内层 IP 协议名（GTP-U 摘要用）
GTP_IP_PROTO_NAMES = {
    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
}

# 单个 TEID 合并输出保留的最大内层字节数（防止大抓包占满内存）
GTP_MERGE_MAX_BYTES = 65536

# GTPv2-C 消息类型
GTPV2_MESSAGE_TYPES = {
    1: "Echo Request", 2: "Echo Response", 3: "Version Not Supported",
    32: "Create Session Request", 33: "Create Session Response",
    34: "Delete Session Request", 35: "Delete Session Response",
    36: "Modify Bearer Request", 37: "Modify Bearer Response",
    38: "Change Notification Request", 39: "Change Notification Response",
}

# GTPv2-C 常用 IE 类型
GTPV2_IE_NAMES = {
    1: "IMSI", 2: "Cause", 3: "Recovery", 71: "APN", 72: "AMBR",
    73: "EPS Bearer ID", 75: "ULI", 77: "RAT Type", 78: "Indication",
    82: "MSISDN", 83: "Bearer QoS", 87: "F-TEID",
}

GTPV2_CAUSE_NAMES = {
    2: "Local Detach", 3: "Complete Detach",
    4: "RAT changed from 3GPP to Non-3GPP",
    5: "ISR Activated", 6: "ISR Deactivated",
    16: "Request accepted", 17: "Request accepted partially",
    18: "New PDN type due to network preference",
    19: "New PDN type due to single address bearer only",
    64: "Context Not Found", 65: "Invalid message format",
    66: "Invalid length", 67: "Service not supported",
    68: "System failure", 69: "No resources available",
    70: "Missing or unknown APN", 71: "Unknown PDN type",
    72: "Try again later", 73: "PDN connection already exists",
    74: "Invalid EPS bearer identity", 95: "Request rejected",
}

GTPV2_AMBR_UNITS = {0: "kbps", 1: "Mbps", 2: "Gbps"}


def _bcd_digits(raw: bytes) -> str:
    """TBCD 解码：每字节低半字节为前一位数字，0xF 表示填充。"""
    out = []
    for byte in raw:
        for nibble in (byte & 0x0F, byte >> 4):
            if nibble == 0x0F:
                continue
            out.append(str(nibble))
    return "".join(out)


def _plmn_text(raw: bytes) -> Optional[str]:
    """3 字节 PLMN（TBCD）→ 'mcc=460 mnc=01'，MNC 高位为 0xF 表示两位。"""
    if len(raw) < 3:
        return None
    low = raw[0] & 0x0F
    high = raw[0] >> 4
    mcc = f"{low}{high}{raw[1] & 0x0F}"
    m1, m2, m3 = raw[1] >> 4, raw[2] & 0x0F, raw[2] >> 4
    mnc = f"{m1}{m2}" if m3 == 0x0F else f"{m1}{m2}{m3}"
    return f"mcc={mcc} mnc={mnc}"


def _uli_text(val: bytes) -> Optional[str]:
    """ULI：长度前缀的分组序列，按长度区分 TAI/ECGI/SAI/RAI。"""
    parts, pos, index = [], 0, 0
    while pos < len(val) and val[pos] and pos + 1 + val[pos] <= len(val):
        size = val[pos]
        seg = val[pos + 1:pos + 1 + size]
        plmn = _plmn_text(seg[:3])
        if plmn and size == 5:
            label = "tai" if index == 0 else "sai"
            parts.append(f"{label}={plmn} tac=0x{int.from_bytes(seg[3:5], 'big'):04x}")
        elif plmn and size == 7:
            parts.append(f"ecgi={plmn} eci=0x{int.from_bytes(seg[3:7], 'big'):08x}")
        elif plmn and size == 6:
            parts.append(f"rai={plmn} lac=0x{int.from_bytes(seg[3:5], 'big'):04x}")
        pos += 1 + size
        index += 1
    return " ".join(parts) or None


def _ambr_field(val: bytes, pos: int) -> str:
    """AMBR 单方向取值：首字节 bit6-5 为单位，低 24 位为数值。"""
    word = struct.unpack_from("!I", val, pos)[0]
    unit = (val[pos] >> 5) & 0x03
    value = word & 0x00FFFFFF
    name = GTPV2_AMBR_UNITS.get(unit)
    return f"{value} {name}" if name else f"{value} unit={unit}"


def _gtpv2_ie_value(ie_type: int, val: bytes) -> Optional[str]:
    """解析常见 GTPv2-C IE 取值，无法解读的类型返回 None。"""
    if ie_type == 1:                                  # IMSI
        return _bcd_digits(val) or None
    if ie_type == 82 and len(val) >= 1:               # MSISDN：首字节 TON/NPI
        return _bcd_digits(val[1:]) or None
    if ie_type == 71:                                 # APN：长度前缀标签序列
        labels, pos = [], 0
        while pos < len(val) and val[pos] and pos + 1 + val[pos] <= len(val):
            labels.append(val[pos + 1:pos + 1 + val[pos]].decode("ascii", "replace"))
            pos += 1 + val[pos]
        return ".".join(labels) or None
    if ie_type == 3 and val:                          # Recovery 重启计数器
        return str(val[0])
    if ie_type == 73 and val:                         # EPS Bearer ID
        return str(val[0])
    if ie_type == 77 and val:                         # RAT Type
        return str(val[0])
    if ie_type == 2 and val:                          # Cause
        return GTPV2_CAUSE_NAMES.get(val[0], f"cause-{val[0]}")
    if ie_type == 87 and len(val) >= 5:               # F-TEID：flags + TEID [+ IPv4]
        teid = struct.unpack_from("!I", val, 1)[0]
        text = f"teid=0x{teid:08x}"
        if val[0] & 0x80 and len(val) >= 9:           # V4 标志位
            text += f" ipv4={'.'.join(str(b) for b in val[5:9])}"
        return text
    if ie_type == 72 and len(val) >= 8:               # AMBR：上行 4 字节 + 下行 4 字节
        return f"ul={_ambr_field(val, 0)} dl={_ambr_field(val, 4)}"
    if ie_type == 83 and len(val) >= 2:               # Bearer QoS：ARP + QCI
        return f"arp={val[0] & 0x3F} qci={val[1] & 0x3F}"
    if ie_type == 78 and val:                         # Indication：标志位原样输出
        return val.hex()
    if ie_type == 75:                                 # ULI
        return _uli_text(val)
    return None

# L7 端口 -> 协议名 映射（TCP）
TCP_PORT_MAP = {
    80: "HTTP", 443: "HTTPS", 8080: "HTTP", 8443: "HTTPS",
    5060: "SIP", 5061: "SIPS",
    22: "SSH", 25: "SMTP", 110: "POP3", 143: "IMAP",
    993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
    53: "DNS", 123: "NTP", 3478: "STUN",
}


def _looks_like_tcp_dns(payload: bytes) -> bool:
    """非标准端口上识别 DNS-over-TCP：2 字节长度前缀 + 合理的 DNS 头部字段。

    消息被切段时前缀长度与实际字节数不等，因此不校验前缀，只校验头部结构。
    """
    if len(payload) < 14:
        return False
    msg_len = struct.unpack_from("!H", payload, 0)[0]
    if msg_len < 12:
        return False
    flags = struct.unpack_from("!H", payload, 4)[0]      # 跳过 2 字节前缀与事务 ID
    qd, an, ns, ar = struct.unpack_from("!HHHH", payload, 6)
    opcode = (flags >> 11) & 0x0F
    if opcode > 6 or not 1 <= qd <= 10:
        return False
    return an <= 100 and ns <= 100 and ar <= 100


def _identify_l7(payload: bytes, dport: Optional[int], sport: Optional[int],
                 is_udp: bool) -> Optional[str]:
    """根据端口号或 payload 特征识别应用层协议。成功返回协议名，否则返回 None。"""
    port_map = UDP_PORT_MAP if is_udp else TCP_PORT_MAP
    
    # 1. 端口匹配优先
    if dport is not None and dport in port_map:
        return port_map[dport]
    if sport is not None and sport in port_map:
        return port_map[sport]
    
    # 2. payload 特征识别
    if len(payload) < 4:
        return None
    
    # DNS 特征：UDP 或裸 DNS 消息的 flags 在偏移 2；
    # TCP 上的 DNS 带 2 字节长度前缀（RFC 1035 §4.2.2），flags 在偏移 4
    dns_offsets = [2]
    if not is_udp and len(payload) >= 14:
        prefix_len = struct.unpack_from("!H", payload, 0)[0]
        if prefix_len == len(payload) - 2:
            dns_offsets.insert(0, 4)
    for fo in dns_offsets:
        if len(payload) >= fo + 2 and struct.unpack_from("!H", payload, fo)[0] & 0x8000:
            return "DNS"
    # 非标准端口：长度前缀未自洽（消息被切段）时靠 DNS 头部结构判断
    if not is_udp and _looks_like_tcp_dns(payload):
        return "DNS"
    
    search_end = min(len(payload), 4096)
    try:
        text = payload[:search_end].decode("ascii", errors="replace")
    except Exception:
        return None
    
    if not text or not text[0].isalpha():
        return None
    
    # HTTP 检测
    if text[:4] in ("GET ", "POST", "PUT ", "DELE", "HEAD") or text.startswith("HTTP/"):
        return "HTTP"
    # SIP 检测
    tokens = text.split()
    if len(tokens) >= 3 and tokens[0] in SIP_METHODS:
        return "SIP"
    if text.startswith("SIP/"):
        return "SIP"
    
    return None


# --------------------------------------------------------------------------- #
# 抓包文件读取
# --------------------------------------------------------------------------- #

@dataclass
class RawPacket:
    index: int
    ts: float          # 绝对时间戳(秒, float)
    data: bytes        # 链路层整帧
    wire_len: int      # 原始线上长度(可能大于 data 长度)
    linktype: int


class CaptureReader:
    """统一读取 pcap / pcapng, 逐包产出 RawPacket。"""

    def __init__(self, path: str):
        self.path = path
        self.endian = "<"
        self.interfaces: list[dict] = []   # pcapng: 每个 IDB 一项
        self.linktypes: list[int] = []
        self.format_name = ""
        self._fh = open(path, "rb")
        magic = self._fh.read(4)
        if magic == PCAPNG_MAGIC:
            self._init_pcapng()
        elif magic in PCAP_MAGICS:
            self._init_pcap(magic)
        else:
            raise ValueError("不是有效的 PCAP/PCAPNG 文件(文件头 magic 不匹配)")

    # -- 初始化 -------------------------------------------------------------

    def _init_pcap(self, magic: bytes) -> None:
        self.endian, self.tsresol, self.format_name = PCAP_MAGICS[magic]
        hdr = self._fh.read(20)
        if len(hdr) < 20:
            raise ValueError("pcap 全局头不完整")
        vmaj, vmin, _tz, _sig, snaplen, network = struct.unpack(
            self.endian + "HHiIII", hdr)
        self.version = f"{vmaj}.{vmin}"
        self.snaplen = snaplen
        self.linktypes = [network]

    def _init_pcapng(self) -> None:
        # 已读 4 字节 block type, 接着是 total_length(4) + byte-order-magic(4)
        head = self._fh.read(8)
        if len(head) < 8:
            raise ValueError("pcapng 文件头不完整")
        bom = head[4:8]
        if bom == b"\x4d\x3c\x2b\x1a":
            self.endian = "<"
        elif bom == b"\x1a\x2b\x3c\x4d":
            self.endian = ">"
        else:
            raise ValueError("pcapng 字节序标记异常")
        total_len = struct.unpack(self.endian + "I", head[:4])[0]
        if total_len < 28 or total_len % 4:
            raise ValueError("pcapng SHB 长度异常")
        self._fh.read(total_len - 12)     # 丢弃剩余 body + 尾部长度
        self.format_name = "pcapng (" + ("小端" if self.endian == "<" else "大端") + ")"

    # -- 遍历 ---------------------------------------------------------------

    def packets(self) -> Iterator[RawPacket]:
        if self.format_name.startswith("pcapng"):
            yield from self._iter_pcapng()
        else:
            yield from self._iter_pcap()

    def _iter_pcap(self) -> Iterator[RawPacket]:
        idx = 0
        while True:
            hdr = self._fh.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_frac, incl, orig = struct.unpack(self.endian + "IIII", hdr)
            data = self._fh.read(incl)
            if len(data) < incl:
                break
            yield RawPacket(idx, ts_sec + ts_frac / self.tsresol, data,
                            orig, self.linktypes[0])
            idx += 1

    def _iter_pcapng(self) -> Iterator[RawPacket]:
        idx = 0
        while True:
            head = self._fh.read(8)
            if len(head) < 8:
                break
            btype = struct.unpack(self.endian + "I", head[:4])[0]
            if btype == 0x0A0D0D0A:                     # SHB: 可能切换字节序
                bom = self._fh.read(4)
                if bom == b"\x4d\x3c\x2b\x1a":
                    self.endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    self.endian = ">"
                total_len = struct.unpack(self.endian + "I", head[4:8])[0]
                self._fh.read(total_len - 12)
                self.interfaces = []
                continue

            blen = struct.unpack(self.endian + "I", head[4:8])[0]
            if blen < 12 or blen % 4:
                break
            rest = self._fh.read(blen - 8)              # body + 尾部重复长度
            if len(rest) < blen - 8:
                break
            body = rest[:-4]                             # 去掉尾部重复长度

            if btype == 1:                               # IDB
                self._parse_idb(body)
            elif btype == 6:                             # EPB
                pkt = self._parse_epb(body, idx)
                if pkt:
                    yield pkt
                    idx += 1
            elif btype == 3:                             # SPB (旧式简单包块)
                if len(body) >= 4:
                    orig = struct.unpack_from(self.endian + "I", body, 0)[0]
                    data = body[4:]
                    iface = self.interfaces[0] if self.interfaces else {"linktype": 1, "resol": 1e6}
                    yield RawPacket(idx, 0.0, data, orig, iface["linktype"])
                    idx += 1
            elif btype == 2:                             # 旧式 Packet Block
                if len(body) >= 20:
                    iface_id = struct.unpack_from(self.endian + "H", body, 0)[0]
                    tsh, tsl, caplen, orig = struct.unpack_from(
                        self.endian + "IIII", body, 4)
                    iface = self._iface(iface_id)
                    ts = ((tsh << 32) | tsl) / iface["resol"]
                    yield RawPacket(idx, ts, body[20:20 + caplen], orig,
                                    iface["linktype"])
                    idx += 1

    # -- pcapng 辅助 --------------------------------------------------------

    def _parse_idb(self, body: bytes) -> None:
        linktype, _, _snaplen = struct.unpack_from(self.endian + "HHI", body, 0)
        resol = 1_000_000.0                              # 默认微秒
        pos = 8
        while pos + 4 <= len(body):
            code, olen = struct.unpack_from(self.endian + "HH", body, pos)
            if code == 0:
                break
            val = body[pos + 4:pos + 4 + olen]
            if code == 9 and olen >= 1:                  # if_tsresol
                raw = val[0]
                resol = float(2 ** (raw & 0x7F)) if raw & 0x80 else float(10 ** raw)
            pos += 4 + ((olen + 3) & ~3)
        self.interfaces.append({"linktype": linktype, "resol": resol})
        self.linktypes.append(linktype)

    def _iface(self, idx: int) -> dict:
        if 0 <= idx < len(self.interfaces):
            return self.interfaces[idx]
        return {"linktype": 1, "resol": 1_000_000.0}

    def _parse_epb(self, body: bytes, idx: int) -> Optional[RawPacket]:
        if len(body) < 20:
            return None
        iface_id, tsh, tsl, caplen, orig = struct.unpack_from(
            self.endian + "IIIII", body, 0)
        iface = self._iface(iface_id)
        ts = ((tsh << 32) | tsl) / iface["resol"]
        return RawPacket(idx, ts, body[20:20 + caplen], orig, iface["linktype"])

    def close(self) -> None:
        self._fh.close()


# --------------------------------------------------------------------------- #
# 解析结果
# --------------------------------------------------------------------------- #

def _ascii_col(chunk: bytes) -> str:
    """把字节转成可打印字符串, 不可打印字节用 '.' 代替。"""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def format_hex(data: bytes, base: int = 0, width: int = 16) -> list[str]:
    """把字节渲染为 `偏移 十六进制 |ASCII|` 形式的展示行。"""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        lines.append(f"{base + i:04x}  {hex_part}  |{_ascii_col(chunk)}|")
    return lines


def format_text(data: bytes, base: int = 0, width: int = 64) -> list[str]:
    """把字节渲染为按可打印字符串展示的行。"""
    lines = []
    for i in range(0, len(data), width):
        lines.append(f"{base + i:04x}  {_ascii_col(data[i:i + width])}")
    return lines


def format_payload(data: bytes, mode: str, base: int = 0,
                   limit: int = 0) -> list[str]:
    """按模式(hex/str/both)把任意 bytes 负荷渲染成展示行; limit<=0 不截断。"""
    shown = data if limit <= 0 else data[:limit]
    lines: list[str] = []
    if mode in ("hex", "both"):
        lines.extend(format_hex(shown, base))
    if mode in ("str", "both"):
        lines.extend(format_text(shown, base))
    if len(shown) < len(data):
        lines.append(f"... 剩余 {len(data) - len(shown)} 字节未显示 "
                     f"(--dump-bytes 0 显示全部)")
    return lines


def payload_block(data: bytes, mode: str, limit: int = 0,
                  base: int = 0) -> dict:
    """把 bytes 负荷打包成 JSON 可序列化的 dump 块。"""
    shown = data if limit <= 0 else data[:limit]
    block = {"offset": base, "total": len(data), "shown": len(shown)}
    if mode in ("hex", "both"):
        block["hex"] = shown.hex()
    if mode in ("str", "both"):
        block["text"] = _ascii_col(shown)
    return block


@dataclass
class PacketInfo:
    index: int
    ts: float
    wire_len: int
    cap_len: int
    l3: str = "-"                    # 网络层协议名, 如 IPv4 / IPv6 / ARP
    l4: str = "-"                    # 传输层协议名, 如 TCP / UDP / SCTP
    src: str = ""
    dst: str = ""
    sport: Optional[int] = None
    dport: Optional[int] = None
    tcp_flags: str = ""              # 例如 "SYN,ACK"
    payload_len: int = 0
    payload_raw: bytes = b""         # 未被进一步解码的载荷(供 --dump 展示)
    payload_off: int = 0             # payload_raw 在整帧中的起始偏移
    gtp_seg: bytes = b""             # GTP-U G-PDU 内层数据(供按 TEID 合并输出)
    gtp_seg_off: int = 0             # gtp_seg 在整帧中的起始偏移
    note: str = ""                   # 附加信息(分片/chunk/PPID 等)
    detail: dict = field(default_factory=dict)

    def to_json(self, dump: Optional[str] = None,
                dump_bytes: int = 256) -> dict:
        out = {
            "index": self.index,
            "time": round(self.ts, 6),
            "src": self.src, "sport": self.sport,
            "dst": self.dst, "dport": self.dport,
            "l3": self.l3, "l4": self.l4,
            "tcp_flags": self.tcp_flags or None,
            "payload_len": self.payload_len,
            "cap_len": self.cap_len, "wire_len": self.wire_len,
            "info": self.note or None,
            "detail": self.detail or None,
        }
        if dump and self.payload_raw:
            out["payload"] = payload_block(self.payload_raw, dump, dump_bytes,
                                           self.payload_off)
        return out

    @property
    def payload(self) -> bytes:
        """统一的未解码负荷字节(Raw/ESP 密文/未知应用层等), 可直接调用。"""
        return self.payload_raw

    def payload_lines(self, mode: str, limit: int = 0) -> list[str]:
        """按 hex/str/both 展示本包负荷。"""
        return format_payload(self.payload, mode, self.payload_off, limit)

    def summary(self) -> str:
        parts = []
        if self.tcp_flags:
            parts.append(f"[{self.tcp_flags}]")
        if self.note:
            parts.append(self.note)
        parts.append(f"len={self.payload_len}")
        return " ".join(parts)


# --------------------------------------------------------------------------- #
# 协议解析
# --------------------------------------------------------------------------- #

def _ip4(raw: bytes) -> str:
    return str(ipaddress.IPv4Address(raw))


def _ip6(raw: bytes) -> str:
    return str(ipaddress.IPv6Address(raw))


def _tcp_flags_str(value: int) -> str:
    return ",".join(name for bit, name in TCP_FLAG_BITS if value & bit)


def _tcp_options(data: bytes, start: int, end: int) -> list[str]:
    opts: list[str] = []
    pos = start
    while pos < end:
        kind = data[pos]
        if kind == 0:
            break
        if kind == 1:
            pos += 1
            continue
        if pos + 1 >= end:
            break
        length = data[pos + 1]
        if length < 2 or pos + length > end:
            break
        body = data[pos + 2:pos + length]
        if kind == 2 and len(body) == 2:
            opts.append(f"MSS={struct.unpack('!H', body)[0]}")
        elif kind == 3 and len(body) == 1:
            opts.append(f"WS={body[0]}")
        elif kind == 4:
            opts.append("SACK_PERM")
        elif kind == 5:
            opts.append("SACK")
        elif kind == 8 and len(body) == 8:
            tsval, tsecr = struct.unpack("!II", body)
            opts.append(f"TS={tsval}/{tsecr}")
        else:
            opts.append(f"OPT-{kind}")
        pos += length
    return opts


def _try_parse_sip(data: bytes, off: int, info: PacketInfo) -> bool:
    """检测并解析 SIP 消息 (RFC 3261)。成功返回 True。"""
    end = min(off + 65536, len(data))
    payload = data[off:end]
    text = None
    try:
        text = payload.decode("ascii")
    except (UnicodeDecodeError, ValueError):
        return False
    lines = text.split("\r\n")
    if not lines:
        return False
    first = lines[0]

    # 请求行: INVITE sip:aa@bb SIP/2.0
    tokens = first.split()
    if len(tokens) >= 3 and tokens[0] in SIP_METHODS:
        info.l4 = "SIP"
        method = tokens[0]
        uri = tokens[1] if len(tokens) > 1 else ""
        sip_ver = ""
        for t in tokens:
            if t.startswith("SIP/"):
                sip_ver = t
                break
        info.note = f"SIP request {method} {uri} {sip_ver}"
        info.detail["sip_type"] = "request"
        info.detail["sip_method"] = method
        info.detail["sip_uri"] = uri
        info.detail["sip_version"] = sip_ver
        if not _extract_sip_body(text, data, off, info):
            return True

    # 响应行: SIP/2.0 200 OK
    if first.startswith("SIP/") and len(tokens) >= 3:
        sip_ver = tokens[0]
        try:
            status_code = int(tokens[1])
        except ValueError:
            return False
        reason = " ".join(tokens[2:]) if len(tokens) > 2 else ""
        info.l4 = "SIP"
        info.note = f"SIP response {status_code} {reason} {sip_ver}"
        info.detail["sip_type"] = "response"
        info.detail["sip_status"] = status_code
        info.detail["sip_status_name"] = SIP_STATUS.get(status_code, str(status_code))
        info.detail["sip_reason"] = reason
        info.detail["sip_version"] = sip_ver
        if not _extract_sip_body(text, data, off, info):
            return True

    return False


def _extract_sip_body(text: str, data: bytes, off: int, info: PacketInfo) -> bool:
    """提取 SIP 消息头域，解析 SDP body。返回 True 表示消息已完整处理。"""
    lines = text.split("\r\n")
    headers_done = -1
    body_len = 0
    for i, line in enumerate(lines):
        if not line:
            headers_done = i + 1
            break
        if line.startswith("Call-ID:"):
            info.detail.setdefault("sip_call_id", "").strip()
            info.detail["sip_call_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("From:"):
            info.detail["sip_from"] = line.split(":", 1)[1].strip()
        elif line.startswith("To:"):
            info.detail["sip_to"] = line.split(":", 1)[1].strip()
        elif line.startswith("Contact:"):
            info.detail["sip_contact"] = line.split(":", 1)[1].strip()
        elif line.startswith("CSeq:"):
            cseq_val = line.split(":", 1)[1].strip()
            cseq_parts = cseq_val.split()
            info.detail.setdefault("sip_cseq", "").strip()
            info.detail["sip_cseq"] = cseq_parts[0] if cseq_parts else cseq_val
            if len(cseq_parts) > 1:
                info.detail.setdefault("sip_cseq_method", "").strip()
                info.detail["sip_cseq_method"] = cseq_parts[1]
        elif line.startswith("Content-Length:"):
            cl = line.split(":", 1)[1].strip()
            if cl.isdigit():
                body_len = int(cl)
                info.detail["sip_body_len"] = body_len
    if "sip_call_id" not in info.detail:
        info.detail["sip_call_id"] = ""

    # 解析 SDP body
    if headers_done >= 0 and body_len > 0:
        # 找到 header 结束在原始文本中的偏移
        header_end = 0
        for i in range(headers_done + 1):
            header_end += len(lines[i]) + 2  # \r\n
        if header_end < len(text):
            body_text = text[header_end:header_end + body_len]
            try:
                _parse_sdp(body_text, info)
            except (UnicodeDecodeError, ValueError, IndexError):
                pass
    return True


def _parse_sdp(sdp_text: str, info: PacketInfo) -> None:
    """解析 SDP 体 (RFC 4566)。提取版本、会话名、连接地址、媒体行等。"""
    sdp_info: dict = {}
    attrs: list[dict] = []
    for line in sdp_text.split("\r\n"):
        if not line:
            continue
        if not line.startswith(" "):  # 忽略 SDP 续行
            kind = line[0]
            data = line[2:] if len(line) > 2 else ""
            if kind == "v":
                sdp_info["version"] = data.strip()
            elif kind == "o":
                parts = data.split()
                if len(parts) >= 6:
                    sdp_info["username"] = parts[0]
                    sdp_info["session_id"] = parts[1]
                    sdp_info["session_version"] = parts[2]
                    sdp_info["nettype"] = parts[3]
                    sdp_info["addrtype"] = parts[4]
                    sdp_info["unicast_addr"] = parts[5]
            elif kind == "s":
                sdp_info["session_name"] = data.strip()
            elif kind == "i":
                sdp_info.setdefault("session_desc", {}).setdefault("subject", data.strip())
            elif kind == "c":
                parts = data.split()
                sdp_info.setdefault("connection", {
                    "nettype": parts[0] if len(parts) > 0 else "",
                    "addrtype": parts[1] if len(parts) > 1 else "",
                    "address": parts[2] if len(parts) > 2 else "",
                })
            elif kind == "t":
                parts = data.split()
                sdp_info["start_time"] = parts[0] if len(parts) > 0 else ""
                sdp_info["stop_time"] = parts[1] if len(parts) > 1 else ""
            elif kind == "m":
                mline = _parse_sdp_mline(data, attrs)
                sdp_info.setdefault("media_lines", []).append(mline)
            elif kind == "a":
                attrs.append(_parse_sdp_attribute(data))

    sdp_info["attributes"] = attrs
    info.detail["sdp_version"] = sdp_info.get("version")
    info.detail["sdp_session"] = sdp_info.get("session_name")
    sdp_addr = sdp_info.get("connection", {}).get("address", "")
    if sdp_addr:
        info.detail["sdp_connection_addr"] = sdp_addr
    media_lines = sdp_info.get("media_lines", [])
    if media_lines:
        info.detail["sdp_media_count"] = len(media_lines)
        for ml in media_lines:
            info.detail.setdefault("sdp_protocols", set()).add(ml.get("protocol"))
            info.detail.setdefault("sdp_codecs", set()).add(ml.get("codec"))
        info.detail["sdp_protocols"] = sorted(info.detail["sdp_protocols"])
        info.detail["sdp_codecs"] = sorted(info.detail["sdp_codecs"])
        # 提取媒体行简写
        lines = []
        for ml in media_lines:
            lines.append(f"{ml.get('type','?')}/{ml.get('port','?')}")
        info.note = " ".join(lines)

    # 音频/视频分开统计
    audio_count = sum(1 for ml in media_lines if ml.get("type") == "audio")
    video_count = sum(1 for ml in media_lines if ml.get("type") == "video")
    if audio_count:
        info.detail["sdp_audio_count"] = audio_count
    if video_count:
        info.detail["sdp_video_count"] = video_count


def _parse_sdp_mline(data: str, attrs: list[dict]) -> dict:
    """解析 SDP media 行: m=audio 49170 RTP/AVP 0 8 96"""
    mline: dict = {}
    parts = data.split()
    if len(parts) < 3:
        return mline
    mline["type"] = parts[0]       # audio/video/application/message
    mline["port"] = parts[1]
    mline["protocol"] = parts[2]
    # 解析 rtpmap/fmtp 属性以获取 codec 名称
    fmt_ids = parts[3:]
    codecs = []
    for fmt_id in fmt_ids:
        codec_name = _sdp_resolve_codec(fmt_id, attrs)
        codecs.append(codec_name or f"pt{fmt_id}")
    mline["codec_ids"] = fmt_ids
    mline["codecs"] = codecs
    info_name = "/".join(codecs[:8])
    if len(codecs) > 8:
        info_name += f"/+{len(codecs) - 8}"
    mline["codec_summary"] = info_name
    return mline


def _sdp_resolve_codec(pt: str, attrs: list[dict]) -> str:
    """通过 a=rtpmap:xx codec/name 或 a=fmtp 查找 PT 对应的 codec 名"""
    rtpmap = int(pt)
    for a in attrs:
        if a.get("key") == "rtpmap" and a.get("value", "").split("/")[0].strip() == pt:
            return a.get("codec", "")
        if a.get("key") == "payload" and a.get("pt") == pt:
            return a.get("codec", "")
    return ""


def _parse_sdp_attribute(data: str) -> dict:
    """解析 SDP a= 属性行"""
    if ":" in data:
        key, value = data.split(":", 1)
    else:
        key, value = data.strip(), ""
    a: dict = {"key": key.strip(), "value": value.strip()}
    # 对 rtpmap 特殊处理，方便查找
    if key.strip() == "rtpmap":
        parts = value.strip().split("/")
        if len(parts) >= 2:
            a["pt"] = parts[0].strip()
            a["codec"] = parts[1].strip()
    elif key.strip() == "fmtp":
        parts = value.strip().split(" ", 1)
        if len(parts) >= 2:
            a["pt"] = parts[0].strip()
            a["fmtp"] = parts[1].strip()
            codec_name = _sdp_resolve_codec(parts[0], [{"key": "rtpmap", "value": value}])
            a["codec"] = codec_name or parts[0].strip()
    elif key.strip() == "csrc-id":
        pass  # 跳过复杂属性
    return a


def _seq_delta(a: int, b: int) -> int:
    """计算 32 位 TCP 序号的带符号差值（a - b），支持序号回绕。"""
    d = (a - b) & 0xFFFFFFFF
    if d >= 0x80000000:
        d -= 0x100000000
    return d


class _FlowBuffer:
    """单条 TCP 流的分段缓存。offset 为相对 base 序号的有符号偏移。"""

    __slots__ = ("base", "last_ts", "segments", "total_bytes", "dropped", "delivered",
                 "expected")

    def __init__(self, base: int, last_ts: float):
        self.base = base
        self.last_ts = last_ts
        self.segments: dict[int, bytes] = {}
        self.total_bytes = 0
        self.dropped = False
        self.delivered: Optional[int] = None   # 已交付到的绝对序号，用于丢弃重传
        self.expected: Optional[int] = None    # 消息总长，末片到达时记录


class ReassemblyCache:
    """按四元组缓存 TCP 分段，用于重组跨段的上层消息。

    key 由调用方构造（如 (src, dst, sport, dport)），缓存内部不解释其含义，
    因此 IPv4/IPv6 或不同方向天然隔离。
    """

    def __init__(self, max_flows: int = 1024, max_bytes_per_flow: int = 65536,
                 idle_timeout: float = 120.0, frag_idle_timeout: float = 60.0):
        self.max_flows = max_flows
        self.max_bytes_per_flow = max_bytes_per_flow
        self.idle_timeout = idle_timeout
        self.frag_idle_timeout = frag_idle_timeout   # RFC 8200 §4.5：分片重组 60 秒
        self._flows: dict[tuple, _FlowBuffer] = {}
        self.evicted_flows = 0
        self.dropped_flows = 0
        self.reuse_resets = 0          # frag_id 复用导致的重建次数

    def put(self, key: tuple, seq: int, payload: bytes, ts: float) -> bool:
        """写入一个分段。返回是否贡献了新数据（纯重传/被丢弃时为 False）。"""
        if not payload:
            return False
        flow = self._flows.get(key)
        if flow is None:
            flow = _FlowBuffer(base=seq, last_ts=ts)
            self._flows[key] = flow
            self._evict_overflow()
        flow.last_ts = ts
        if flow.dropped:
            return False
        is_frag = self._is_frag_key(key)
        offset = _seq_delta(seq, flow.base)
        if flow.delivered is not None:
            d = _seq_delta(seq, flow.delivered)
            if d < 0:
                # 与已交付区域重叠：整段丢弃，或裁掉重叠头部
                trim = -d
                if trim >= len(payload):
                    return False
                seq += trim
                payload = payload[trim:]
                offset = _seq_delta(seq, flow.base)
        if offset in flow.segments:
            existing = flow.segments[offset]
            if payload[:len(existing)] != existing[:len(payload)]:
                if is_frag and seq != 0:
                    # 非首片内容冲突：RFC 8200 §4.5 要求重叠分片整体丢弃
                    self._invalidate(key)
                    return False
                # 首片内容不同：另一次报文复用了同一 ID，旧数据作废后重建
                self.close(key)
                self.reuse_resets += 1
                flow = _FlowBuffer(base=seq, last_ts=ts)
                self._flows[key] = flow
                offset = 0
            else:
                # 内容一致的重复分片：按重传处理（抓包重复采样常见，不判废）
                if len(payload) <= len(existing):
                    return False
                payload = payload[len(existing):]
                offset += len(existing)
                if offset in flow.segments:
                    return False
        # 与已有区间部分重叠：内容一致视为重传，内容不同则整包作废
        for off, chunk in flow.segments.items():
            lo = max(offset, off)
            hi = min(offset + len(payload), off + len(chunk))
            if lo < hi:
                if payload[lo - offset:hi - offset] == chunk[lo - off:hi - off]:
                    break
                if is_frag and seq != 0:
                    self._invalidate(key)
                    return False
                self.close(key)
                self.reuse_resets += 1
                flow = _FlowBuffer(base=seq, last_ts=ts)
                self._flows[key] = flow
                offset = 0
                break
        flow.segments[offset] = payload
        flow.total_bytes += len(payload)
        if flow.total_bytes > self.max_bytes_per_flow:
            flow.dropped = True
            flow.segments.clear()
            flow.total_bytes = 0
            self.dropped_flows += 1
            return False
        return True

    def put_first(self, key: tuple, seq: int, payload: bytes, ts: float) -> bool:
        """写入位于偏移 0 的首片。

        同一 key 已缓存内容不同的首片时，视为 frag_id 被另一组报文复用，清空重建。
        """
        flow = self._flows.get(key)
        if flow is not None:
            for off, chunk in flow.segments.items():
                if flow.base + off == 0:
                    if chunk != payload:
                        self.close(key)
                        self.reuse_resets += 1
                    break
        return self.put(key, seq, payload, ts)

    def set_total(self, key: tuple, total: int) -> None:
        """记录该流的数据总长（末片到达时设置），使任意到达顺序都能判定完成。"""
        flow = self._flows.get(key)
        if flow is not None:
            flow.expected = total

    def starts_at_zero(self, key: tuple) -> bool:
        """缓存数据是否从绝对偏移 0 开始（即首片是否已到达）。"""
        flow = self._flows.get(key)
        return bool(flow and flow.segments and flow.base + min(flow.segments) == 0)

    def ready(self, key: tuple) -> Optional[bytes]:
        """已缓存数据达到记录的总长时返回完整数据，否则返回 None。

        要求数据从绝对偏移 0 开始（分片场景的语义），避免把半截数据当成完整消息。
        """
        flow = self._flows.get(key)
        if flow is None or flow.dropped or flow.expected is None:
            return None
        if not flow.segments or flow.base + min(flow.segments) != 0:
            return None
        return self.take(key, expect_len=flow.expected)

    def take(self, key: tuple, expect_len: Optional[int] = None) -> Optional[bytes]:
        """返回从最小偏移开始的连续字节。

        遇到空洞即停止拼接；指定 expect_len 且连续长度不足时返回 None。
        """
        flow = self._flows.get(key)
        if flow is None or flow.dropped or not flow.segments:
            return None
        start = min(flow.segments)
        buf = bytearray()
        nxt = start
        for offset in sorted(flow.segments):
            data = flow.segments[offset]
            end = offset + len(data)
            if end <= nxt:  # 完全被已有数据覆盖
                continue
            if offset > nxt:  # 出现空洞，停止
                break
            buf.extend(data[nxt - offset:])
            nxt = end
        if expect_len is not None and len(buf) < expect_len:
            return None
        return bytes(buf)

    def contiguous_len(self, key: tuple) -> int:
        """返回当前可用的连续字节数（用于判断还缺多少）。"""
        data = self.take(key)
        return len(data) if data else 0

    def consume(self, key: tuple, n: int) -> None:
        """从连续区间前端丢弃 n 字节（消息解析完成后调用）。"""
        flow = self._flows.get(key)
        if flow is None or n <= 0 or not flow.segments:
            return
        target = min(flow.segments) + n
        segments: dict[int, bytes] = {}
        for offset, data in flow.segments.items():
            end = offset + len(data)
            if end <= target:  # 整段已被消费
                continue
            if offset < target:
                segments[target] = data[target - offset:]
            else:
                segments[offset] = data
        flow.segments = segments
        flow.total_bytes = sum(len(v) for v in segments.values())
        flow.delivered = (flow.base + target) & 0xFFFFFFFF

    def segment_count(self, key: tuple) -> int:
        flow = self._flows.get(key)
        return len(flow.segments) if flow else 0

    def flow_count(self) -> int:
        return len(self._flows)

    def has_flow(self, key: tuple) -> bool:
        """该四元组是否已有缓存条目（用于后续段的协议延续判断）。"""
        return key in self._flows

    def _invalidate(self, key: tuple) -> None:
        """作废该数据报：RFC 8200 §4.5 要求重叠或越界分片整体丢弃，不再重组。"""
        flow = self._flows.get(key)
        if flow is None:
            return
        flow.segments.clear()
        flow.total_bytes = 0
        flow.expected = None
        flow.dropped = True
        self.dropped_flows += 1

    def is_invalid(self, key: tuple) -> bool:
        """该数据报是否因不符合 RFC 约束被作废。"""
        flow = self._flows.get(key)
        return bool(flow and flow.dropped)

    def close(self, key: tuple) -> None:
        """连接结束（FIN/RST）时清理该流缓存。"""
        self._flows.pop(key, None)

    def evict_expired(self, now: float) -> int:
        """清理空闲超时的流，返回清理数量。last_ts 恰好等于 now-idle 时保留。

        分片重组按 RFC 8200 §4.5 使用更短的 60 秒超时。
        """
        expired = [k for k, f in self._flows.items()
                   if now - f.last_ts > self._timeout_for(k)]
        for k in expired:
            del self._flows[k]
        self.evicted_flows += len(expired)
        return len(expired)

    def _timeout_for(self, key: tuple) -> float:
        if self._is_frag_key(key):
            return self.frag_idle_timeout
        return self.idle_timeout

    @staticmethod
    def _is_frag_key(key: tuple) -> bool:
        return isinstance(key[0], str) and key[0].startswith("gtp-frag")

    def _evict_overflow(self) -> None:
        while len(self._flows) > self.max_flows:
            oldest = min(self._flows, key=lambda k: self._flows[k].last_ts)
            del self._flows[oldest]
            self.evicted_flows += 1


def _parse_tcp(data: bytes, off: int, end: int, info: PacketInfo,
               cache: Optional[ReassemblyCache] = None) -> None:
    info.l4 = "TCP"
    if end - off < 20:
        info.note = "头部截断"
        return
    sport, dport, seq, ack, off_flags = struct.unpack_from("!HHIIH", data, off)
    hlen = (off_flags >> 12) * 4
    if hlen < 20:
        hlen = 20
    flags = off_flags & 0x1FF
    win, _csum, urg = struct.unpack_from("!HHH", data, off + 14)
    info.sport, info.dport = sport, dport
    info.tcp_flags = _tcp_flags_str(flags)
    info.payload_len = max(0, end - off - hlen)
    info.detail.update({
        "seq": seq, "ack": ack, "window": win,
        "header_len": hlen, "flags": info.tcp_flags,
        "options": _tcp_options(data, off + 20, off + min(hlen, end - off)),
    })
    if urg:
        info.detail["urgent_pointer"] = urg

    key = (info.src, info.dst, sport, dport) if cache is not None else None

    # 连接生命周期：SYN 开启新连接、RST 立即终止，两者都清理陈旧缓存
    if cache is not None and flags & 0x06:
        cache.close(key)

    # 应用层协议自动识别（L7）
    if info.payload_len > 0:
        payload = data[off + hlen:end]
        l7_name = _identify_l7(payload, dport, sport, is_udp=False)
        if l7_name == "HTTP":
            _try_parse_http_tcp(data, off + hlen, end - off, info)
        elif l7_name == "SIP":
            _try_parse_sip_tcp(data, off + hlen, end - off, info)
        elif l7_name == "DNS":
            _handle_tcp_dns(data, off + hlen, end, info, seq, flags, cache)
        elif cache is not None and cache.has_flow(key):
            # 该四元组已在做 DNS 重组：后续段特征识别失败也继续投递
            _handle_tcp_dns(data, off + hlen, end, info, seq, flags, cache)
        elif l7_name:
            info.l4 = l7_name
            info.note = f"L7={l7_name} port={dport}"
        else:
            # 未识别应用层：保留 TCP 载荷原始字节，供 --dump 展示
            info.payload_raw, info.payload_off = payload, off + hlen

    # FIN 表示发送方不再发送数据：本段载荷处理完后释放该方向缓存
    if cache is not None and flags & 0x01:
        cache.close(key)


def _handle_tcp_dns(data: bytes, pstart: int, pend: int, info: PacketInfo,
                    seq: int, flags: int, cache: Optional[ReassemblyCache]) -> None:
    """TCP DNS 解析。

    有缓存上下文时按四元组做流重组，支持跨段、乱序、粘包；
    无缓存时退化为单段解析（旧行为）。
    """
    payload = data[pstart:pend]

    if cache is None:
        dns_off = pstart
        # 长度前缀与实际长度自洽时才跳过（RFC 1035 §4.2.2）
        if pend - pstart >= 14:
            prefix = struct.unpack_from("!H", data, pstart)[0]
            if prefix == pend - pstart - 2:
                dns_off = pstart + 2
        msg = data[dns_off:pend]
        if _parse_dns(msg, 0, len(msg), info):
            info.l4 = "DNS"
            return
        info.note = f"DNS 解析失败 payload={info.payload_len}B"
        return

    key = (info.src, info.dst, info.sport, info.dport)
    if not cache.put(key, seq, payload, info.ts):
        return                    # 纯重传或已丢弃，不产生等待提示
    buf = cache.take(key)
    if buf is None:
        info.note = "DNS 等待缺段"
        return

    parsed = 0
    pos = 0
    while len(buf) - pos >= 2:
        msg_len = struct.unpack_from("!H", buf, pos)[0]
        if msg_len < 12:            # 前缀不可信，停止推进
            break
        if len(buf) - pos < 2 + msg_len:
            break                   # 消息尚未收全
        msg = buf[pos + 2:pos + 2 + msg_len]
        target = info if parsed == 0 else PacketInfo(
            index=info.index, ts=info.ts, wire_len=0, cap_len=0)
        if not _parse_dns(msg, 0, len(msg), target):
            break
        parsed += 1
        pos += 2 + msg_len

    if parsed == 0:
        info.note = f"DNS 等待后续段 {len(buf)}B"
        return

    cache.consume(key, pos)
    info.l4 = "DNS"
    if parsed > 1:
        info.detail["dns_messages"] = parsed
        info.note = f"重组 {parsed} 条 DNS 消息"


def _try_parse_sip_tcp(data: bytes, off: int, payload_len: int, info: PacketInfo) -> None:
    """SIP over TCP 粘包/分帧处理。
    从 TCP payload 中查找所有 SIP 消息（可能有多条消息粘在一起），
    按 '\r\n\r\n' 作为头体分隔符解析。
    注意：每次只解析最后一条 SIP 消息（粘包情况下，前面的非 SIP 数据直接跳过）。
    """
    end = off + payload_len
    # 扫描所有可能的 SIP 消息
    pos = off
    sip_data_start = -1
    sip_data_end = -1
    found_sip = False

    while pos + 1 < end:
        # 在剩余 8KB 内查找
        search_end = min(pos + 8192, end)
        payload_slice = data[pos:search_end]
        text = None
        try:
            text = payload_slice.decode("ascii")
        except (UnicodeDecodeError, ValueError):
            break

        # 查找第一行（SIP 请求或响应）
        first_newline = text.find("\r\n")
        if first_newline < 0:
            break  # 等待更多数据

        first_line = text[:first_newline]
        tokens = first_line.split()
        is_sip = False

        if len(tokens) >= 3 and tokens[0] in SIP_METHODS:
            is_sip = True
        elif first_line.startswith("SIP/") and len(tokens) >= 3:
            try:
                int(tokens[1])
                is_sip = True
            except ValueError:
                pass

        if not is_sip:
            pos += 1  # 跳过非 SIP 数据
            continue

        # 找到 SIP 消息起始位置
        sip_data_start = pos
        found_sip = True

        # 查找 header 结束标记
        header_end_marker = text.find("\r\n\r\n")
        if header_end_marker < 0:
            pos += first_newline + 1  # 等待更多数据
            continue

        header_part = text[:header_end_marker]
        lines = header_part.split("\r\n")

        # 提取头域和 Content-Length
        body_len = 0
        for line in lines[1:]:
            if line.startswith("Call-ID:"):
                info.detail.setdefault("sip_call_id", "").strip()
                info.detail["sip_call_id"] = line.split(":", 1)[1].strip()
            elif line.startswith("From:"):
                info.detail["sip_from"] = line.split(":", 1)[1].strip()
            elif line.startswith("To:"):
                info.detail["sip_to"] = line.split(":", 1)[1].strip()
            elif line.startswith("Contact:"):
                info.detail["sip_contact"] = line.split(":", 1)[1].strip()
            elif line.startswith("CSeq:"):
                cseq_val = line.split(":", 1)[1].strip()
                cseq_parts = cseq_val.split()
                info.detail.setdefault("sip_cseq", "").strip()
                info.detail["sip_cseq"] = cseq_parts[0] if cseq_parts else cseq_val
                if len(cseq_parts) > 1:
                    info.detail.setdefault("sip_cseq_method", "").strip()
                    info.detail["sip_cseq_method"] = cseq_parts[1]
            elif line.startswith("Content-Length:"):
                cl = line.split(":", 1)[1].strip()
                if cl.isdigit():
                    body_len = int(cl)

        # 计算 body 在原始字节中的结束位置
        body_offset = header_end_marker + 4  # \r\n\r\n = 4 bytes
        if body_len > 0:
            sip_data_end = sip_data_start + header_end_marker + 4 + body_len
        else:
            sip_data_end = sip_data_start + header_end_marker + 4

        # 移动到下一条消息
        pos = sip_data_start + header_end_marker + 4

    # 只解析最后一条 SIP 消息的数据
    if found_sip and sip_data_start >= 0 and sip_data_end >= 0:
        sip_raw = data[sip_data_start:min(sip_data_end, end)]
        _parse_sip_message(sip_raw, info)


def _try_parse_http_tcp(data: bytes, off: int, payload_len: int, info: PacketInfo) -> bool:
    """检测 TCP payload 是否为 HTTP 消息。"""
    if payload_len < 4:
        return False
    search_end = min(off + 4096, off + payload_len)
    payload_slice = data[off:search_end]
    try:
        text = payload_slice.decode("ascii", errors="replace")
    except Exception:
        return False

    if not text or not text[0].isalpha():
        return False

    # 尝试解析完整 HTTP 消息 (header 结束 + body)
    lines = text.split("\r\n")
    first_line = lines[0]
    tokens = first_line.split()
    if not tokens:
        return False

    # 检测请求行或响应行
    is_http = False
    if len(tokens) >= 2 and tokens[-1].startswith("HTTP/"):
        is_http = True
    elif first_line.startswith("HTTP/"):
        is_http = True

    if not is_http:
        return False

    # 尝试找到完整消息
    body_start = text.find("\r\n\r\n")
    if body_start < 0:
        return False

    # 解析并更新 info
    return _parse_http(data, off, off + payload_len, info)


def _parse_sip_message(sip_raw: bytes, info: PacketInfo) -> None:
    """解析单条 SIP over TCP 消息。"""
    text = None
    try:
        text = sip_raw.decode("ascii")
    except (UnicodeDecodeError, ValueError):
        return

    lines = text.split("\r\n")
    if not lines:
        return

    first_line = lines[0]
    tokens = first_line.split()

    if len(tokens) >= 3 and tokens[0] in SIP_METHODS:
        info.l4 = "SIP"
        method, uri, sip_ver = tokens[0], tokens[1], ""
        for t in tokens:
            if t.startswith("SIP/"):
                sip_ver = t
                break
        info.note = f"SIP request {method} {uri} {sip_ver}"
        info.detail["sip_type"] = "request"
        info.detail["sip_method"] = method
        info.detail["sip_uri"] = uri
        info.detail["sip_version"] = sip_ver
    elif first_line.startswith("SIP/") and len(tokens) >= 3:
        info.l4 = "SIP"
        sip_ver, status_code, reason = tokens[0], 0, ""
        try:
            status_code = int(tokens[1])
            reason = " ".join(tokens[2:]) if len(tokens) > 2 else ""
        except ValueError:
            pass
        info.note = f"SIP response {status_code} {reason} {sip_ver}"
        info.detail["sip_type"] = "response"
        info.detail["sip_status"] = status_code
        info.detail["sip_status_name"] = SIP_STATUS.get(status_code, str(status_code))
        info.detail["sip_reason"] = reason
        info.detail["sip_version"] = sip_ver
    else:
        return

    # 提取头域
    header_end = -1
    body_len = 0
    for i, line in enumerate(lines):
        if not line:
            header_end = i + 1
            break
        if line.startswith("Call-ID:"):
            info.detail.setdefault("sip_call_id", "").strip()
            info.detail["sip_call_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("From:"):
            info.detail["sip_from"] = line.split(":", 1)[1].strip()
        elif line.startswith("To:"):
            info.detail["sip_to"] = line.split(":", 1)[1].strip()
        elif line.startswith("Contact:"):
            info.detail["sip_contact"] = line.split(":", 1)[1].strip()
        elif line.startswith("CSeq:"):
            cseq_val = line.split(":", 1)[1].strip()
            cseq_parts = cseq_val.split()
            info.detail.setdefault("sip_cseq", "").strip()
            info.detail["sip_cseq"] = cseq_parts[0] if cseq_parts else cseq_val
            if len(cseq_parts) > 1:
                info.detail.setdefault("sip_cseq_method", "").strip()
                info.detail["sip_cseq_method"] = cseq_parts[1]
        elif line.startswith("Content-Length:"):
            cl = line.split(":", 1)[1].strip()
            if cl.isdigit():
                body_len = int(cl)

    if "sip_call_id" not in info.detail:
        info.detail["sip_call_id"] = ""

    # 解析 SDP body
    if header_end > 0 and body_len > 0:
        header_end_offset = 0
        for i in range(header_end + 1):
            header_end_offset += len(lines[i]) + 2
        if header_end_offset + body_len <= len(text):
            body_text = text[header_end_offset:header_end_offset + body_len]
            try:
                _parse_sdp(body_text, info)
            except (UnicodeDecodeError, ValueError, IndexError):
                pass


def _parse_dns(data: bytes, off: int, end: int, info: PacketInfo) -> bool:
    """解析 DNS 消息 (RFC 1035)。成功返回 True。"""
    if end - off < 12:
        return False
    txn_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH", data, off)
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF

    info.detail["dns_id"] = txn_id
    info.detail["dns_opcode"] = opcode
    info.detail["dns_rcode"] = rcode
    info.detail["dns_rcode_name"] = DNS_RCODES.get(rcode, str(rcode))
    info.detail["dns_qr"] = "response" if qr else "query"
    info.detail["dns_qdcount"] = qdcount
    info.detail["dns_ancount"] = ancount
    info.detail["dns_nscount"] = nscount
    info.detail["dns_arcount"] = arcount

    if qr:
        info.note = f"DNS response rcode={info.detail['dns_rcode_name']}"
    else:
        info.note = f"DNS query opcode={opcode}"

    pos = off + 12
    domains: list[str] = []
    answers: list[str] = []

    # 解析查询段
    for _ in range(min(qdcount, 20)):
        name, pos = _parse_dns_name(data, pos, end)
        if name is None:
            break
        if pos + 4 > end:
            break
        qtype, qclass = struct.unpack_from("!HH", data, pos)
        info.detail[f"query_{len(domains)}_type"] = DNS_QTYPES.get(qtype, str(qtype))
        info.detail[f"query_{len(domains)}_class"] = DNS_QCLASSES.get(qclass, str(qclass))
        info.detail[f"query_{len(domains)}_name"] = name
        domains.append(name)
        pos += 4

    # 解析回答段
    for _ in range(min(ancount, 50)):
        if pos >= end:
            break
        name, pos = _parse_dns_rr_name(data, pos, end)
        if pos + 10 > end:
            break
        rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, pos)
        pos += 10
        if rdlength == 0 or pos + rdlength > end:
            continue
        rdata = data[pos:pos + rdlength]
        pos += rdlength

        rdata_text = _dns_parse_rdata(rtype, rdata)
        answers.append(f"{name} → {rdata_text}")
        info.detail[f"answer_{len(answers)}"] = f"{name} {rdata_text}"

    info.detail["queries"] = domains[:10]
    info.detail["answers"] = answers[:50]
    if domains:
        info.note = f"DNS {'response' if qr else 'query'} for {','.join(domains[:3])}"
    if answers:
        info.note += f" ans={len(answers)}"
    return True


def _parse_dns_name(data: bytes, off: int, end: int) -> tuple[Optional[str], int]:
    """解析 DNS 域名（支持压缩指针）。返回 (name, next_off)。"""
    labels: list[str] = []
    pos = off
    jumped = False
    saved_pos = None
    limit = off + 256  # 防止过深嵌套
    jumps = 0          # 压缩指针跳转次数，防止自指/互指循环

    while off < end and off < limit:
        if off + 1 > end:
            return None, pos
        label_len = data[off]
        if label_len == 0:
            off += 1
            break
        if (label_len & 0xC0) == 0xC0:  # 压缩指针
            if off + 1 >= end:
                break
            jumps += 1
            if jumps > 8:  # 防止压缩指针循环（自指或互指）
                return None, pos
            ptr = struct.unpack_from("!H", data, off)[0] & 0x3FFF
            if not jumped:
                saved_pos = off + 2
            off = ptr
            jumped = True
            continue
        if (label_len & 0xC0) != 0:
            return None, pos  # 非压缩指针保留
        off += 1
        if off + label_len > end:
            return None, pos
        labels.append(data[off:off + label_len].decode("ascii", errors="replace"))
        off += label_len

    name = ".".join(labels) if labels else "."
    next_off = saved_pos if jumped else off
    if jumped:
        return name, (saved_pos or off)
    return name, next_off


def _parse_dns_rr_name(data: bytes, off: int, end: int) -> tuple[Optional[str], int]:
    """解析资源记录的域名（同上但允许从任何位置开始压缩）"""
    return _parse_dns_name(data, off, end)


def _dns_parse_rdata(rtype: int, rdata: bytes) -> str:
    """解析 DNS 记录数据。"""
    if rtype == 1 and len(rdata) == 4:  # A
        return ".".join(str(b) for b in rdata)
    if rtype == 28 and len(rdata) == 16:  # AAAA
        return str(ipaddress.IPv6Address(rdata))
    if rtype in (2, 5, 12, 15, 16, 33, 41, 43, 46, 47, 48, 64, 65):  # 文本类型
        try:
            return rdata.decode("utf-8", errors="replace")[:128]
        except Exception:
            return rdata.hex()[:128]
    if rtype == 3:  # CNAME → A (简化)
        return rdata.hex()[:128]
    return rdata.hex()[:128]


def _try_parse_rtcp(data: bytes, off: int, end: int, info: PacketInfo) -> bool:
    """检测并解析 RTCP 包 (RFC 3550)。成功返回 True。"""
    if end - off < 8:
        return False
    # RTCP SR/RR 首字节: V=2(0x80), 第二位 P, Count(4 bit)
    vh_pt = data[off]
    ver = vh_pt >> 6
    if ver != 2:
        return False
    # 第二个字节可能是 PT (192-202, 207)
    pt = data[off + 1]
    if pt < 192 or pt > 207 or pt == 199 or pt == 203:
        return False
    # 至少一个 RTCP header (SSRC = 4 bytes + type/length = 4 bytes)
    if end - off < 8:
        return False
    info.l4 = "RTCP"
    _parse_rtcp(data, off, end, info)
    return True


def _parse_rtp(data: bytes, off: int, end: int, info: PacketInfo) -> bool:
    """解析 RTP 头部 (RFC 3550)。成功返回 True。"""
    if end - off < 12:
        return False

    ver_p_x_cc, m_pt, seq, tstamp, ssrc = struct.unpack_from(
        "!BBHII", data, off)

    # Byte 0: V(2) P(1) X(1) CC(4)
    ver = (ver_p_x_cc >> 6) & 0x3
    cc = ver_p_x_cc & 0xF
    # Byte 1: M(1) PT(7)
    m_bit = (m_pt >> 7) & 1
    pt = m_pt & 0x7F

    if ver != 2:
        return False

    info.l4 = "RTP"
    info.detail["rtp_version"] = ver
    info.detail["rtp_cc"] = cc
    info.detail["rtp_m_bit"] = m_bit
    info.detail["rtp_pt"] = pt
    info.detail["rtp_pt_name"] = RTP_PAYLOAD_NAMES.get(pt, f"PT{pt}")
    info.detail["rtp_seq"] = seq
    info.detail["rtp_timestamp"] = tstamp
    info.detail["rtp_ssrc"] = ssrc

    # RTCP 检测：奇数端口通常为 RTCP
    if info.dport and (info.dport % 2 != 0):
        info.l4 = "RTCP"
        _parse_rtcp(data, off, end, info)
        return True

    # 解析扩展头
    pos = off + 12
    if cc:
        for _ in range(cc):
            if pos + 4 > end:
                break
            ext_id, ext_len = struct.unpack_from("!BB", data, pos)
            pos += 4 + (ext_len - 1) * 4  # skip extension

    info.note = f"RTP seq={seq} ts={tstamp} pt={info.detail['rtp_pt_name']} ssrc={ssrc:08x} {len(data) - off}B"
    return True


def _parse_rtcp(data: bytes, off: int, end: int, info: PacketInfo) -> None:
    """解析 RTCP 头部 (RFC 3550)。"""
    ssrcs: list[int] = []

    pos = off
    while pos + 4 <= end:
        vh_pt = data[pos]
        rtcp_type = data[pos + 1]
        length = 0
        if pos + 3 < end:
            length = struct.unpack_from("!H", data, pos + 2)[0]

        rtcp_name = RTCP_TYPES.get(rtcp_type, f"RTCP-{rtcp_type}")
        info.detail.setdefault("rtcp_types", []).append(rtcp_name)

        if rtcp_type in (192, 193):  # SR / RR
            if pos + 24 < end:
                sender_ssrc = struct.unpack_from("!I", data, pos + 4)[0]
                ssrcs.append(sender_ssrc)
                info.detail["rtcp_ssrc"] = sender_ssrc
                if rtcp_type == 192:  # SR: NTP(8) + RTP-ts(4) + pkt-count(4) + byte-count(4)
                    ntp_hi = struct.unpack_from("!I", data, pos + 8)[0]
                    ntp_lo = struct.unpack_from("!I", data, pos + 12)[0]
                    info.detail["rtcp_ntp_ts"] = (ntp_hi << 32) | ntp_lo
                    info.detail["rtcp_rtp_ts"] = struct.unpack_from("!I", data, pos + 16)[0]
                else:  # RR: SSRC(4) + frac-lost+lost+last-seq(4) + jitter(4) + LSR(4) + DLSR(4)
                    info.detail["rtcp_rr_count"] = vh_pt & 0x1F
                info.note = f"RTCP {rtcp_name} ssrc={sender_ssrc:08x} length={length + 1}"
        elif rtcp_type == 195:  # BYE
            reason_ssrc = struct.unpack_from("!I", data, pos + 4)[0]
            ssrcs.append(reason_ssrc)
            info.note = f"RTCP {rtcp_name}"
            # Parse reason string (starts after SSRC + RC(1) + padding)
            body_start = pos + 8
            if body_start < end:
                reason = data[body_start:end - off].decode("ascii", errors="replace")
                if reason:
                    info.note += f" reason={reason.strip()}"
        elif rtcp_type == 196:  # APP
            if pos + 8 < end:
                app_ssrc = struct.unpack_from("!I", data, pos + 4)[0]
                ssrcs.append(app_ssrc)
                info.note = f"RTCP {rtcp_name} ssrc={app_ssrc:08x}"
        elif rtcp_type in (200, 201):  # RTPFB / PSFB
            info.note = f"RTCP {rtcp_name}"
        elif rtcp_type == 194:  # SDES
            if pos + 4 < end:
                ssrc = struct.unpack_from("!I", data, pos + 4)[0]
                ssrcs.append(ssrc)
                info.note = f"RTCP {rtcp_name} ssrc={ssrc:08x}"
        else:
            info.note = f"RTCP {rtcp_name} length={length}"

        pos += 4 * (length + 1)

    if not info.note:
        info.note = f"RTCP ssrcs={len(ssrcs)}"
    info.detail["rtcp_ssrcs"] = ssrcs


def _parse_http(data: bytes, off: int, end: int, info: PacketInfo) -> bool:
    """解析 HTTP 请求/响应。成功返回 True。"""
    if end - off < 10:
        return False

    payload_slice = data[off:end]
    try:
        text = payload_slice.decode("ascii", errors="replace")
    except Exception:
        return False

    lines = text.split("\r\n")
    if not lines:
        return False

    first_line = lines[0]
    tokens = first_line.split()
    if not tokens:
        return False

    # 请求行: GET /path HTTP/1.1
    if len(tokens) >= 2 and tokens[-1].startswith("HTTP/"):
        info.l4 = "HTTP"
        method = tokens[0]
        uri = tokens[1] if len(tokens) > 1 else ""
        version = tokens[-1]
        info.note = f"HTTP {method} {uri} {version}"
        info.detail["http_type"] = "request"
        info.detail["http_method"] = method
        info.detail["http_uri"] = uri
        info.detail["http_version"] = version
    elif first_line.startswith("HTTP/"):
        # 响应行: HTTP/1.1 200 OK
        info.l4 = "HTTP"
        version = tokens[0]
        try:
            status_code = int(tokens[1])
        except (ValueError, IndexError):
            status_code = 0
        reason = " ".join(tokens[2:]) if len(tokens) > 2 else ""
        info.note = f"HTTP {version} {status_code} {reason}"
        info.detail["http_type"] = "response"
        info.detail["http_version"] = version
        info.detail["http_status"] = status_code
        info.detail["http_reason"] = reason
    else:
        return False

    # 解析头部
    body_start = text.find("\r\n\r\n")
    body_len = 0
    content_type = ""
    content_encoding = ""
    host = ""
    user_agent = ""
    referer = ""
    location = ""
    content_length = 0

    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            hname, hval = line.split(":", 1)
            hname_lower = hname.strip().lower()
            hval = hval.strip()
            if hname_lower == "content-type":
                content_type = hval
                info.detail["http_content_type"] = content_type
            elif hname_lower == "content-length":
                try:
                    content_length = int(hval)
                except ValueError:
                    pass
                info.detail["http_content_length"] = content_length
            elif hname_lower == "content-encoding":
                content_encoding = hval
            elif hname_lower == "host":
                host = hval
                info.detail["http_host"] = host
            elif hname_lower == "user-agent":
                user_agent = hval
                info.detail["http_user_agent"] = user_agent[:100]
            elif hname_lower == "referer":
                referer = hval
            elif hname_lower == "location":
                location = hval
                info.detail["http_redirect_location"] = hval
            elif hname_lower == "server":
                info.detail["http_server"] = hval[:100]
            elif hname_lower == "date":
                info.detail["http_date"] = hval[:64]
            elif hname_lower == "set-cookie":
                info.detail.setdefault("http_set_cookies", []).append(hval[:100])
            elif hname_lower == "connection":
                info.detail["http_connection"] = hval

    if "http_set_cookies" in info.detail:
        info.detail["http_set_cookies"] = info.detail["http_set_cookies"][:5]

    # 解析 HTTP 体 (如果存在)
    if content_length > 0 and body_start >= 0 and body_start + 4 + content_length <= len(text):
        body_text = text[body_start + 4:body_start + 4 + content_length]
        _parse_http_body(body_text, content_type, content_encoding, info)

    return True


def _parse_http_body(body_text: str, content_type: str, content_encoding: str,
                     info: PacketInfo) -> None:
    """解析 HTTP 体内容。"""
    if content_type.startswith("text/html"):
        info.detail["http_body_type"] = "HTML"
        # 提取 title 和链接数
        title = ""
        if "<title>" in body_text:
            try:
                start = body_text.index("<title>") + 7
                end_tag = body_text.index("</title>", start)
                title = body_text[start:end_tag]
            except ValueError:
                pass
        if title:
            info.detail["http_title"] = title[:100]
        link_count = body_text.lower().count("<a") + body_text.lower().count('<img')
        if link_count:
            info.detail["http_elements"] = link_count
    elif content_type.startswith("text/plain"):
        info.detail["http_body_type"] = "TEXT"
    elif content_type.startswith("application/json"):
        info.detail["http_body_type"] = "JSON"
        try:
            body_data = body_text.split("\r\n")[0] if "\r\n" in body_text else body_text
            data_obj = json.loads(body_data[:4096])
            if isinstance(data_obj, dict):
                for k in list(data_obj.keys())[:10]:
                    v = data_obj[k]
                    if isinstance(v, (str, int, float, bool)):
                        info.detail[f"http_json_{k}"] = str(v)[:100]
                    elif isinstance(v, list) and v:
                        info.detail[f"http_json_{k}"] = f"[{type(v[0]).__name__}]"
                info.detail["http_json_keys"] = len(data_obj)
        except (json.JSONDecodeError, Exception):
            info.detail["http_body_type"] = "JSON_PARSE_FAILED"
    elif content_type.startswith("application/xml") or content_type.startswith("text/xml"):
        info.detail["http_body_type"] = "XML"
    elif content_type.startswith("text/css"):
        info.detail["http_body_type"] = "CSS"
    elif content_type.startswith("application/javascript") or content_type.startswith("text/javascript"):
        info.detail["http_body_type"] = "JavaScript"
    elif content_type.startswith("image/"):
        info.detail["http_body_type"] = f"IMAGE({content_type.split('/')[-1]})"
    elif content_type.startswith("video/"):
        info.detail["http_body_type"] = f"VIDEO({content_type.split('/')[-1]})"
    elif content_type.startswith("audio/"):
        info.detail["http_body_type"] = f"AUDIO({content_type.split('/')[-1]})"


def _parse_udp(data: bytes, off: int, end: int, info: PacketInfo,
               cache: Optional[ReassemblyCache] = None) -> None:
    info.l4 = "UDP"
    if end - off < 8:
        info.note = "头部截断"
        return
    sport, dport, ulen, _csum = struct.unpack_from("!HHHH", data, off)
    info.sport, info.dport = sport, dport
    info.payload_len = (ulen - 8) if ulen >= 8 else max(0, end - off - 8)
    if ulen == 0:
        info.note = "JumboGram(长度字段为 0)"
        info.payload_len = max(0, end - off - 8)
        return
    
    payload = data[off + 8:end]
    l7_name = _identify_l7(payload, dport, sport, is_udp=True)
    # 动态端口上的 RTP/RTCP 兜底探测（端口不在映射表内时靠 payload 结构判定）
    dynamic_rtp = (
        dport is not None
        and (10000 <= dport < 65535 or dport in (5004, 5005, 8000, 8001, 8002, 8003))
    )
    
    # 特定协议优先处理
    if l7_name == "DNS":
        if _parse_dns(data, off + 8, end, info):
            info.l4 = "DNS"
            return
        info.note = f"DNS 解析失败 payload={len(payload)}B"
    elif l7_name == "SIP":
        if _try_parse_sip(data, off + 8, info):
            return
    elif l7_name in ("RTP", "RTCP") or (l7_name is None and dynamic_rtp):
        if l7_name == "RTCP" or (dport and dport % 2 != 0):
            if _try_parse_rtcp(data, off + 8, end, info):
                return
        if _parse_rtp(data, off + 8, end, info):
            return
    elif l7_name == "GTP-U":
        if _parse_gtp(data, off + 8, end, info, cache):
            info.l4 = "GTP-U"
            return
    elif l7_name == "GTP-C":
        if _parse_gtp_c(data, off + 8, end, info):
            info.l4 = "GTP-C"
            return
    elif l7_name == "NAT-T":
        _parse_natt(data, off + 8, end, info)
        return
    elif l7_name == "HTTP":
        # HTTP over TCP 通常在 _parse_tcp 处理，但 UDP HTTP3/QUIC 可能到达这里
        info.note = f"UDP payload {info.payload_len}B (HTTP3/QUIC?)"
    elif l7_name:
        # 端口有映射但未在上述特定分支处理
        info.l4 = l7_name
        info.note = f"UDP L7={l7_name} port={dport}"

    # 未解码的 UDP 载荷保留原始字节，供 --dump 展示
    if info.l4 == "UDP" and payload and not info.payload_raw:
        info.payload_raw, info.payload_off = payload, off + 8


def _parse_gtp(data: bytes, off: int, end: int, info: PacketInfo,
               cache: Optional[ReassemblyCache] = None) -> bool:
    """GTP-U 拆解：公共头、可选字段/扩展头，以及 G-PDU 内层 IP 摘要。"""
    if end - off < 8:
        info.note = "GTP 头部截断"
        return False
    b0, mtype, glen, teid = struct.unpack_from("!BBHI", data, off)
    has_ext = bool(b0 & 0x04)
    has_seq = bool(b0 & 0x02)
    has_npdu = bool(b0 & 0x01)
    detail = {
        "gtp_version": (b0 >> 5) & 0x07,
        "gtp_type": GTP_MESSAGE_TYPES.get(mtype, f"0x{mtype:02X}"),
        "gtp_length": glen,
        "gtp_teid": f"0x{teid:08x}",
    }

    pos = off + 8
    if has_ext or has_seq or has_npdu:
        if end - pos < 4:
            info.detail.update(detail)
            info.note = "GTP 可选字段截断"
            return False
        seq, npdu, next_ext = struct.unpack_from("!HBB", data, pos)
        if has_seq:
            detail["gtp_sequence"] = seq
        if has_npdu:
            detail["gtp_npdu"] = npdu
        pos += 4
        # 扩展头链：每层 1 字节长度（4 字节为单位），末字节为下一层类型，0 表示结束
        guard = 0
        while has_ext and next_ext and guard < 8 and pos < end:
            ext_len = data[pos] * 4
            if ext_len == 0 or pos + ext_len > end:
                break
            next_ext = data[pos + ext_len - 1]
            pos += ext_len
            guard += 1

    note = f"GTP {detail['gtp_type']} teid=0x{teid:08x}"
    if mtype == 0xFF and pos < end:
        inner = _gtp_inner_summary(data, pos, end, detail, teid, cache, info.ts)
        if inner:
            note += f" | inner {inner}"
        raw = detail.pop("_inner_raw", None)
        if raw:
            info.payload_raw = raw
            info.payload_off = detail.pop("_inner_raw_off", 0)
        # 保留完整内层数据(含内层 IP 头), 供按 TEID 合并输出
        info.gtp_seg = data[pos:end]
        info.gtp_seg_off = pos
    info.detail.update(detail)
    info.note = note
    return True


def _gtp_inner_l4(data: bytes, off: int, end: int, proto: int, detail: dict) -> str:
    """解析内层传输层头，返回形如 `TCP 1234->80 [PA]` 的描述。"""
    if proto == 6 and end - off >= 20:
        sport, dport = struct.unpack_from("!HH", data, off)
        flags = _tcp_flags_str(data[off + 13])
        detail.update({"gtp_inner_sport": sport, "gtp_inner_dport": dport,
                       "gtp_inner_tcp_flags": flags})
        return f"TCP {sport}->{dport} [{flags}]"
    if proto == 17 and end - off >= 8:
        sport, dport = struct.unpack_from("!HH", data, off)
        detail.update({"gtp_inner_sport": sport, "gtp_inner_dport": dport})
        return f"UDP {sport}->{dport}"
    if proto in (1, 58) and end - off >= 4:
        itype, icode = data[off], data[off + 1]
        detail.update({"gtp_inner_icmp_type": itype, "gtp_inner_icmp_code": icode})
        return f"ICMP type={itype} code={icode}"
    # 内层未被解码(ESP / AH / 未知协议)：保留原始字节，供 --dump 展示
    detail["_inner_raw_off"] = off
    detail["_inner_raw"] = data[off:end]
    return ""


def _strip_ipv6_ext(data: bytes, end: int, nxt: int) -> tuple:
    """遍历 IPv6 扩展头链（不含分片头），返回 `(上层协议偏移, 上层协议号)`。"""
    pos = 0
    for _ in range(8):
        if nxt in (0, 43, 60, 135):
            if pos + 8 > end:
                return pos, nxt
            hlen = (data[pos + 1] + 1) * 8
        elif nxt == 51:
            if pos + 8 > end:
                return pos, nxt
            hlen = (data[pos + 1] + 2) * 4
        else:
            return pos, nxt
        nxt = data[pos]
        pos += hlen
    return pos, nxt


def _gtp_inner_summary(data: bytes, off: int, end: int, detail: dict,
                       teid: int = 0,
                       cache: Optional[ReassemblyCache] = None,
                       ts: float = 0.0) -> str:
    """提取 G-PDU 内层 IP 头与传输层摘要；内层 IPv4 分片时按偏移重组。"""
    version = data[off] >> 4
    if version == 4:
        if end - off < 20:
            return ""
        ihl = (data[off] & 0x0F) * 4
        total = struct.unpack_from("!H", data, off + 2)[0]
        ip_id = struct.unpack_from("!H", data, off + 4)[0]
        frag = struct.unpack_from("!H", data, off + 6)[0]
        frag_off = frag & 0x1FFF
        more = bool(frag & 0x2000)
        proto = data[off + 9]
        src = str(ipaddress.IPv4Address(data[off + 12:off + 16]))
        dst = str(ipaddress.IPv4Address(data[off + 16:off + 20]))
        name = GTP_IP_PROTO_NAMES.get(proto, str(proto))
        detail.update({
            "gtp_inner_version": 4,
            "gtp_inner_proto": name,
            "gtp_inner_src": src,
            "gtp_inner_dst": dst,
            "gtp_inner_len": total,
        })
        if frag_off or more:
            desc = f"IPv4 {name} 分片(offset={frag_off * 8}, more={int(more)})"
            body = data[off + ihl:end]
            end_len = frag_off * 8 + len(body)
            if end_len > 65535 or (more and len(body) % 8):
                detail["gtp_inner_frag_invalid"] = True
                reason = "超出 65535" if end_len > 65535 else "非末片长度非 8 倍数"
                return f"{desc} 分片作废({reason})"
            if cache is not None:
                key = ("gtp-frag", teid, src, dst, ip_id, proto)
                if frag_off == 0:
                    cache.put_first(key, 0, body, ts)
                else:
                    cache.put(key, frag_off * 8, body, ts)
                if not more:
                    cache.set_total(key, end_len)
                got = cache.ready(key)
                if got is not None:
                    cache.close(key)
                    detail["gtp_inner_frag_len"] = len(got)
                    desc += f" 重组完成={len(got)}B"
                elif cache.is_invalid(key):
                    detail["gtp_inner_frag_invalid"] = True
                    desc += " 分片作废(重叠)"
                elif not cache.starts_at_zero(key):      # 首片尚未到达
                    detail["gtp_inner_frag_headless"] = True
                    desc += " 缺首片"
            return desc
        l4 = _gtp_inner_l4(data, off + ihl, end, proto, detail)
        return f"IPv4 {l4 or name} len={total}"
    if version == 6:
        if end - off < 40:
            return ""
        plen = struct.unpack_from("!H", data, off + 4)[0]
        nxt = data[off + 6]
        inner_end = min(off + 40 + plen, end) if plen else end
        pos = off + 40
        exts = 0
        frag_off = 0
        frag_more = False
        frag_id = 0
        frag_nxt = 0
        frag_data_pos = pos
        src = str(ipaddress.IPv6Address(data[off + 8:off + 24]))
        dst = str(ipaddress.IPv6Address(data[off + 24:off + 40]))

        # 下钻 IPv6 扩展头链，定位真正的上层协议
        while True:
            if nxt == 44:                                 # Fragment，固定 8 字节
                if pos + 8 > inner_end:
                    detail["gtp_inner_ext_truncated"] = True
                    break
                frag_bits = struct.unpack_from("!H", data, pos + 2)[0]
                frag_off = frag_bits >> 3
                frag_more = bool(frag_bits & 0x0001)
                frag_id = struct.unpack_from("!I", data, pos + 4)[0]
                frag_nxt = data[pos]                      # 可分片部分的第一个头
                frag_data_pos = pos + 8                   # 分片偏移的时间起点
                nxt = frag_nxt
                pos += 8
                if frag_off:                              # 非首片不含后续扩展头，停止下钻
                    break
            elif nxt in (0, 43, 60, 135):                 # HopByHop/Routing/DestOpts/Mobility
                if pos + 8 > inner_end:
                    detail["gtp_inner_ext_truncated"] = True
                    break
                nxt, hlen = data[pos], (data[pos + 1] + 1) * 8
                pos += hlen
                exts += 1
            elif nxt == 51:                               # AH
                if pos + 8 > inner_end:
                    detail["gtp_inner_ext_truncated"] = True
                    break
                nxt, hlen = data[pos], (data[pos + 1] + 2) * 4
                pos += hlen
                exts += 1
            else:
                break
            if exts > 8:                                  # 防御性上限
                break

        name = GTP_IP_PROTO_NAMES.get(nxt, str(nxt))
        detail.update({
            "gtp_inner_version": 6,
            "gtp_inner_src": src,
            "gtp_inner_dst": dst,
            "gtp_inner_len": plen,
        })
        if not frag_off:                                  # 非首片无法确定最终上层协议
            detail["gtp_inner_proto"] = name
        if exts:
            detail["gtp_inner_ext"] = exts
        if frag_off or frag_more:
            detail["gtp_inner_frag_offset"] = frag_off * 8
            head = ""
            if frag_off == 0:
                # 首片携带完整传输层头，可先给出端口
                l4 = _gtp_inner_l4(data, pos, inner_end, nxt, detail)
                head = f" {l4 or name}"
            desc = f"IPv6{head} 分片(offset={frag_off * 8}, more={int(frag_more)})"
            body = data[frag_data_pos:inner_end]        # 偏移从可分片部分起点计
            end_len = frag_off * 8 + len(body)
            if end_len > 65535 or (frag_more and len(body) % 8):
                detail["gtp_inner_frag_invalid"] = True
                reason = "超出 65535" if end_len > 65535 else "非末片长度非 8 倍数"
                return f"{desc} 分片作废({reason}) len={plen}"
            if cache is not None:
                key = ("gtp-frag6", teid, src, dst, frag_id)
                if frag_off == 0:
                    cache.put_first(key, 0, body, ts)
                else:
                    cache.put(key, frag_off * 8, body, ts)
                if not frag_more:
                    cache.set_total(key, end_len)
                got = cache.ready(key)                   # 任意顺序下都可判定完成
                if got is not None:
                    cache.close(key)
                    detail["gtp_inner_frag_len"] = len(got)
                    # 重组后剥离可分片部分起始处的扩展头，再定位传输层
                    l4_off, l4_proto = _strip_ipv6_ext(got, len(got), frag_nxt)
                    if l4_off:
                        detail["gtp_inner_ext_in_frag"] = l4_off
                    l4 = _gtp_inner_l4(got, l4_off, len(got), l4_proto, detail)
                    final_name = GTP_IP_PROTO_NAMES.get(l4_proto, str(l4_proto))
                    detail["gtp_inner_proto"] = final_name
                    final = l4 or final_name
                    desc = f"IPv6 {final} 分片(offset={frag_off * 8}, more={int(frag_more)})" \
                           f" 重组完成={len(got)}B"
                elif cache.is_invalid(key):
                    detail["gtp_inner_frag_invalid"] = True
                    desc += " 分片作废(重叠)"
                elif not cache.starts_at_zero(key):      # 首片尚未到达
                    detail["gtp_inner_frag_headless"] = True
                    desc += " 缺首片"
            return f"{desc} len={plen}"
        l4 = _gtp_inner_l4(data, pos, inner_end, nxt, detail)
        return f"IPv6 {l4 or name} len={plen}"
    return ""


def _parse_gtp_c(data: bytes, off: int, end: int, info: PacketInfo) -> bool:
    """GTPv2-C 拆解：版本/消息类型/TEID/序列号 + IE 列表。"""
    if end - off < 8:
        info.note = "GTPv2 头部截断"
        return False
    b0, mtype, glen = struct.unpack_from("!BBH", data, off)
    version = (b0 >> 5) & 0x07
    if version != 2:
        info.note = f"GTP 版本非 2 (v{version})"
        return False
    has_teid = bool(b0 & 0x08)
    detail = {
        "gtpv2_type": GTPV2_MESSAGE_TYPES.get(mtype, f"0x{mtype:02X}"),
        "gtpv2_length": glen,
    }

    pos = off + 4
    if has_teid:
        if end - pos < 4:
            info.detail.update(detail)
            info.note = "GTPv2 TEID 截断"
            return False
        detail["gtpv2_teid"] = f"0x{struct.unpack_from('!I', data, pos)[0]:08x}"
        pos += 4
    if end - pos < 4:
        info.detail.update(detail)
        info.note = "GTPv2 序列号截断"
        return False
    seq = int.from_bytes(data[pos:pos + 3], "big")
    detail["gtpv2_sequence"] = seq
    pos += 4

    ies = []
    ie_values = {}
    while pos + 3 <= end and len(ies) < 64:
        ie_type = data[pos]
        raw_len = struct.unpack_from("!H", data, pos + 1)[0]
        ie_len = raw_len & 0x0FFF
        instance = (raw_len >> 12) & 0x0F
        if pos + 3 + ie_len > end:
            detail["gtpv2_ie_truncated"] = True
            break
        name = GTPV2_IE_NAMES.get(ie_type, f"IE-{ie_type}")
        ies.append(name)
        value = _gtpv2_ie_value(ie_type, data[pos + 3:pos + 3 + ie_len])
        if value is not None:
            # 同类型 IE 可有多个实例，非 0 实例加后缀区分
            ie_values[name if instance == 0 else f"{name}#{instance}"] = value
        pos += 3 + ie_len
    if ies:
        detail["gtpv2_ies"] = ies
    if ie_values:
        detail["gtpv2_ie_values"] = ie_values

    note = f"GTPv2-C {detail['gtpv2_type']} seq={seq}"
    if has_teid:
        note += f" teid={detail['gtpv2_teid']}"
    if ies:
        more = "..." if len(ies) > 4 else ""
        note += f" | IE {len(ies)}个: {', '.join(ies[:4])}{more}"
    info.detail.update(detail)
    info.note = note
    return True


def _parse_sctp(data: bytes, off: int, end: int, info: PacketInfo) -> None:
    info.l4 = "SCTP"
    if end - off < 12:
        info.note = "头部截断"
        return
    sport, dport, vtag, _csum = struct.unpack_from("!HHII", data, off)
    info.sport, info.dport = sport, dport
    info.detail.update({"verification_tag": vtag})

    chunks: list[str] = []
    payload_total = 0
    pos = off + 12
    while pos + 4 <= end:
        ctype, cflags, clen = struct.unpack_from("!BBH", data, pos)
        if clen < 4:
            break
        body = data[pos + 4:min(pos + clen, end)]
        cname = SCTP_CHUNKS.get(ctype, f"CHUNK-{ctype}")
        chunks.append(cname)
        if ctype in (0, 64) and len(body) >= 12:          # DATA / I_DATA
            tsn, sid, ssn, ppid = struct.unpack("!IHHI", body[:12])
            payload = len(body) - 12
            payload_total += payload
            info.detail.setdefault("streams", set()).add(sid)
            info.detail["ppid"] = ppid
            info.detail["ppid_name"] = SCTP_PPIDS.get(ppid, str(ppid))
            info.detail["tsn"] = tsn
            info.note = (f"DATA sid={sid} ssn={ssn} ppid={ppid}"
                         f"({info.detail['ppid_name']}) payload={payload}")
        elif ctype == 1 and len(body) >= 12:              # INIT
            itag, a_rwnd, os_, is_ = struct.unpack("!IIHH", body[:12])
            info.detail.update({"init_tag": itag, "a_rwnd": a_rwnd,
                                "out_streams": os_, "in_streams": is_})
            info.note = f"INIT streams_out={os_} streams_in={is_}"
        elif ctype == 2 and len(body) >= 12:              # INIT_ACK
            itag, a_rwnd, os_, is_ = struct.unpack("!IIHH", body[:12])
            info.detail.update({"init_tag": itag, "a_rwnd": a_rwnd,
                                "out_streams": os_, "in_streams": is_})
            info.note = f"INIT_ACK streams_out={os_} streams_in={is_}"
        elif ctype == 3 and len(body) >= 12:              # SACK
            cum_tsn, a_rwnd, n_gap, n_dup = struct.unpack("!IIHH", body[:12])
            info.detail.update({"cum_tsn": cum_tsn, "a_rwnd": a_rwnd,
                                "gap_blocks": n_gap, "dup_tsns": n_dup})
            info.note = f"SACK cum_tsn={cum_tsn} gap={n_gap}"
        elif ctype == 7 and len(body) >= 4:               # SHUTDOWN
            info.detail["cum_tsn"] = struct.unpack("!I", body[:4])[0]

        pos += (clen + 3) & ~3

    if info.detail.get("streams"):
        info.detail["streams"] = sorted(info.detail["streams"])
    info.detail["chunks"] = chunks
    info.payload_len = payload_total or max(0, end - off - 12)
    if not info.note and chunks:
        info.note = "chunks=" + ",".join(chunks)


def _parse_icmp4(data: bytes, off: int, end: int, info: PacketInfo) -> None:
    info.l4 = "ICMP"
    info.payload_len = max(0, end - off)
    if end - off < 4:
        return
    itype, code, _csum = struct.unpack_from("!BBH", data, off)
    name = ICMP4_TYPES.get(itype, f"type={itype}")
    info.detail.update({"type": itype, "code": code, "type_name": name})
    info.note = f"{name} code={code}"


def _parse_icmp6(data: bytes, off: int, end: int, info: PacketInfo) -> None:
    info.l4 = "ICMPv6"
    info.payload_len = max(0, end - off)
    if end - off < 4:
        return
    itype, code, _csum = struct.unpack_from("!BBH", data, off)
    name = ICMP6_TYPES.get(itype, f"type={itype}")
    info.detail.update({"type": itype, "code": code, "type_name": name})
    info.note = f"{name} code={code}"


def _parse_natt(data: bytes, off: int, end: int, info: PacketInfo) -> None:
    """NAT-T 解封装 (RFC 3948)。

    UDP 4500 上可能承载三种内容:
      * 单字节 0xFF        -> NAT Keepalive
      * 4 字节非 ESP 标记  -> 其后为 IKE 报文
      * 其余               -> 直接是 ESP 报文(无标记)
    非 ESP 标记的长度门槛取 IKE 头最小长度 28 字节, 避免把 SPI=0 的短
    ESP 报文误判成 IKE。
    """
    seg_len = end - off
    if seg_len == 0:
        info.l4 = "NAT-T"
        info.note = "NAT-T 空载荷"
        return
    if seg_len == 1 and data[off] == 0xFF:
        info.l4 = "NAT-T"
        info.note = "NAT-T Keepalive"
        return
    if seg_len >= 28 and data[off:off + 4] == b"\x00\x00\x00\x00":
        info.l4 = "IKE"
        info.note = f"NAT-T non-ESP marker, IKE 载荷 {seg_len - 4}B"
        info.payload_raw, info.payload_off = data[off + 4:end], off + 4
        return
    _parse_esp(data, off, end, info)
    info.detail["natt"] = True
    info.note = f"NAT-T {info.note}"


def _parse_esp(data: bytes, off: int, end: int, info: PacketInfo) -> None:
    """ESP 头解析 (RFC 4303)。

    加密域内的 Padding / Pad Length / Next Header / ICV 未解密时不可读,
    这里只解析明文的 SPI 与序列号, 密文部分原样保留供 --dump 展示。
    """
    info.l4 = "ESP"
    info.payload_len = max(0, end - off)
    if end - off < 8:
        info.note = "ESP 头部截断"
        info.payload_raw, info.payload_off = data[off:end], off
        return
    spi, seq = struct.unpack_from("!II", data, off)
    cipher_len = max(0, end - off - 8)
    info.detail.update({
        "esp_spi": f"0x{spi:08x}",
        "esp_seq": seq,
        "esp_cipher_len": cipher_len,
    })
    info.note = f"ESP spi=0x{spi:08x} seq={seq} 密文={cipher_len}B"
    if cipher_len:
        info.payload_raw, info.payload_off = data[off + 8:end], off + 8


def _parse_transport(data: bytes, off: int, end: int, proto: int,
                     info: PacketInfo,
                     cache: Optional[ReassemblyCache] = None) -> None:
    """按 IP 协议号分发到具体传输层解析器。"""
    if proto == 6:
        _parse_tcp(data, off, end, info, cache)
    elif proto == 17:
        _parse_udp(data, off, end, info, cache)
    elif proto == 132:
        _parse_sctp(data, off, end, info)
    elif proto == 1:
        _parse_icmp4(data, off, end, info)
    elif proto == 58:
        _parse_icmp6(data, off, end, info)
    elif proto == 50:
        _parse_esp(data, off, end, info)
    elif proto == 136:
        info.l4 = "UDPLite"
        info.payload_len = max(0, end - off - 8)
    else:
        # AH / GRE / 未知协议：载荷无法进一步解码，保留原始字节
        info.l4 = IP_PROTO_NAMES.get(proto, f"IP-proto-{proto}")
        info.payload_len = max(0, end - off)
        info.payload_raw, info.payload_off = data[off:end], off


def _parse_ipv4(data: bytes, off: int, info: PacketInfo,
                cache: Optional[ReassemblyCache] = None) -> None:
    if len(data) < off + 20:
        info.l3 = "IPv4"
        info.note = "头部截断"
        return
    ihl = (data[off] & 0x0F) * 4
    if ihl < 20:
        info.l3 = "IPv4"
        info.note = "IHL 非法"
        return
    tot = struct.unpack_from("!H", data, off + 2)[0]
    proto = data[off + 9]
    info.l3 = "IPv4"
    info.src = _ip4(data[off + 12:off + 16])
    info.dst = _ip4(data[off + 16:off + 20])

    frag = struct.unpack_from("!H", data, off + 6)[0]
    frag_offset = frag & 0x1FFF
    more_frag = bool(frag & 0x2000)
    info.detail["ttl"] = data[off + 8]
    info.detail["ip_proto"] = proto

    payload_off = off + ihl
    payload_end = min(off + tot, len(data)) if tot >= ihl else len(data)
    if frag_offset:                                   # 非首片: 无传输层头
        info.l4 = "IPv4-frag"
        info.payload_len = max(0, payload_end - payload_off)
        info.note = f"分片数据(offset={frag_offset * 8})"
        info.payload_raw, info.payload_off = data[payload_off:payload_end], payload_off
        return
    if more_frag:
        info.note = "分片(首片)"
    _parse_transport(data, payload_off, payload_end, proto, info, cache)


def _parse_ipv6(data: bytes, off: int, info: PacketInfo,
                cache: Optional[ReassemblyCache] = None) -> None:
    if len(data) < off + 40:
        info.l3 = "IPv6"
        info.note = "头部截断"
        return
    payload_len = struct.unpack_from("!H", data, off + 4)[0]
    nxt = data[off + 6]
    info.l3 = "IPv6"
    info.src = _ip6(data[off + 8:off + 24])
    info.dst = _ip6(data[off + 24:off + 40])

    end = min(off + 40 + payload_len, len(data)) if payload_len else len(data)
    pos = off + 40
    frag_offset = 0
    expansion = 0
    # 遍历扩展头链
    while True:
        if nxt == 44:                                 # Fragment
            if pos + 8 > end:
                break
            frag_off = struct.unpack_from("!H", data, pos + 2)[0] >> 3
            frag_offset = frag_off
            nxt = data[pos]
            pos += 8
        elif nxt in (0, 43, 60, 135):                 # HopByHop/Routing/DestOpts/Mobility
            if pos + 8 > end:
                break
            nxt, hlen = data[pos], (data[pos + 1] + 1) * 8
            pos += hlen
            expansion += 1
        elif nxt == 51:                               # AH
            if pos + 8 > end:
                break
            nxt, hlen = data[pos], (data[pos + 1] + 2) * 4
            pos += hlen
            expansion += 1
        else:
            break

    info.detail["next_header"] = nxt
    if expansion:
        info.detail["ext_headers"] = expansion
    if frag_offset:
        info.l4 = "IPv6-frag"
        info.payload_len = max(0, end - pos)
        info.note = f"分片数据(offset={frag_offset * 8})"
        info.payload_raw, info.payload_off = data[pos:end], pos
        return
    if nxt == 59:                                     # No Next Header
        info.l4 = "IPv6-NoNxt"
        info.payload_len = max(0, end - pos)
        return
    _parse_transport(data, pos, end, nxt, info, cache)


def _parse_arp(data: bytes, off: int, info: PacketInfo) -> None:
    info.l3 = "ARP"
    if len(data) < off + 8:
        return
    # Standard ARP body: sha(6) + spa(4) + htype(2) + ptype(2) + hlen(1) + plen(1) + opcode(2) + tha(6) + tpa(4)
    #                       off+0        off+6       off+10     off+14    off+15    off+16    off+18     off+24
    if len(data) < off + 28:
        return
    opcode = struct.unpack_from("!H", data, off + 16)[0]
    ops = {1: "Request", 2: "Reply", 3: "RARP-Request", 4: "RARP-Reply"}
    name = ops.get(opcode, f"op={opcode}")
    info.note = f"ARP {name}"
    info.payload_len = max(0, len(data) - off - 28)
    if opcode in (1, 2):
        spa = _ip4(data[off + 6:off + 10])
        tpa = _ip4(data[off + 24:off + 28])
        info.src, info.dst = spa, tpa
        info.detail.update({"sender_ip": spa, "target_ip": tpa})
        info.note = f"ARP {name} {spa} -> {tpa}"


def _strip_vlan(data: bytes) -> tuple[int, int, int]:
    """剥掉以太网头与 VLAN 标签, 返回 (ethertype, 偏移, vlan 层数)。"""
    ethertype = struct.unpack_from("!H", data, 12)[0]
    off = 14
    vlans = 0
    while ethertype in ETH_VLAN and len(data) >= off + 4:
        ethertype = struct.unpack_from("!H", data, off + 2)[0]
        off += 4
        vlans += 1
    return ethertype, off, vlans


def parse_packet(raw: RawPacket,
                 cache: Optional[ReassemblyCache] = None) -> PacketInfo:
    """把链路层整帧解析成 PacketInfo。"""
    info = PacketInfo(raw.index, raw.ts, raw.wire_len, len(raw.data))
    data = raw.data
    if not data:
        return info

    lt = raw.linktype
    ethertype, off, vlans = None, 0, 0

    if lt == 1:                                        # Ethernet
        if len(data) < 14:
            info.note = "帧头截断"
            return info
        ethertype, off, vlans = _strip_vlan(data)
    elif lt in (0, 108):                               # NULL / LOOP (4 字节地址族)
        off = 4
        if len(data) < off + 1:
            return info
        family = struct.unpack_from("<I", data, 0)[0]
        if family > 0xFFFF:
            family = struct.unpack_from(">I", data, 0)[0]
        ethertype = {2: ETH_IPV4, 24: ETH_IPV6, 28: ETH_IPV6, 30: ETH_IPV6}.get(family)
    elif lt in (101, 228, 229):                        # RAW IP
        ver = data[0] >> 4
        off = 0
        ethertype = ETH_IPV4 if ver == 4 else (ETH_IPV6 if ver == 6 else None)
    elif lt == 113:                                    # Linux SLL
        if len(data) < 16:
            return info
        ethertype = struct.unpack_from("!H", data, 14)[0]
        off = 16
    elif lt == 276:                                    # Linux SLL2
        if len(data) < 20:
            return info
        ethertype = struct.unpack_from("!H", data, 0)[0]
        off = 20
    else:
        info.l3 = f"LINKTYPE-{lt}"
        info.note = "未支持的链路层"
        return info

    if vlans:
        info.detail["vlan_tags"] = vlans

    if ethertype is None:
        info.l3 = "Unknown"
        info.note = "无法识别上层协议"
        return info

    if ethertype == ETH_IPV4:
        _parse_ipv4(data, off, info, cache)
    elif ethertype == ETH_IPV6:
        _parse_ipv6(data, off, info, cache)
    elif ethertype == ETH_ARP:
        _parse_arp(data, off, info)
    else:
        info.l3 = ETHERTYPE_NAMES.get(ethertype, f"EtherType-0x{ethertype:04x}")
        info.payload_len = max(0, len(data) - off)
        info.payload_raw, info.payload_off = data[off:], off
    return info


# --------------------------------------------------------------------------- #
# 统计与展示
# --------------------------------------------------------------------------- #

@dataclass
class GtpTeidMerge:
    """单个 TEID 的 G-PDU 内层数据合并记录。"""
    teid: str
    packets: int = 0
    bytes: int = 0                            # 内层数据总字节数
    merged: bytearray = field(default_factory=bytearray)
    truncated: bool = False                   # 是否因上限未全部保留
    seq_first: Optional[int] = None
    seq_last: Optional[int] = None
    seq_jumps: int = 0                        # 序列号非 +1 递增次数(丢包/重传/乱序)
    prev_seq: Optional[int] = None
    flows: Counter = field(default_factory=Counter)
    inner_protos: Counter = field(default_factory=Counter)

    @property
    def payload(self) -> bytes:
        """已合并的内层负荷字节。"""
        return bytes(self.merged)

    def payload_lines(self, mode: str, limit: int = 0) -> list[str]:
        """按 hex/str/both 展示合并后的内层负荷。"""
        return format_payload(self.payload, mode, 0, limit)

    def add(self, info: PacketInfo) -> None:
        seg = info.gtp_seg
        self.packets += 1
        self.bytes += len(seg)
        room = GTP_MERGE_MAX_BYTES - len(self.merged)
        if room > 0:
            self.merged += seg[:room]
            if len(seg) > room:
                self.truncated = True
        else:
            self.truncated = True

        seq = info.detail.get("gtp_sequence")
        if isinstance(seq, int):
            if self.seq_first is None:
                self.seq_first = seq
            self.seq_last = seq
            if self.prev_seq is not None and ((seq - self.prev_seq) & 0xFFFF) != 1:
                self.seq_jumps += 1
            self.prev_seq = seq

        proto = info.detail.get("gtp_inner_proto")
        if proto:
            self.inner_protos[proto] += 1
        src = info.detail.get("gtp_inner_src")
        dst = info.detail.get("gtp_inner_dst")
        if src and dst:
            sport = info.detail.get("gtp_inner_sport")
            dport = info.detail.get("gtp_inner_dport")
            if sport is not None and dport is not None:
                # IPv6 地址加方括号, 避免与端口分隔符混淆
                a = f"[{src}]:{sport}" if ":" in src else f"{src}:{sport}"
                b = f"[{dst}]:{dport}" if ":" in dst else f"{dst}:{dport}"
                label = f"{proto or '?'} {a}->{b}"
            else:
                label = f"{proto or '?'} {src}->{dst}"
            self.flows[label] += 1


class Statistics:
    def __init__(self) -> None:
        self.count = 0
        self.bytes = 0
        self.l3 = Counter()
        self.l4 = Counter()
        self.tcp_flags = Counter()
        self.ports = Counter()          # (l4, 目的端口)
        self.flows: dict[tuple, list] = {}
        self.sctp_chunks = Counter()
        self.sctp_ppids = Counter()
        self.sip_methods = Counter()
        self.sip_status = Counter()
        self.rtcp_types = Counter()
        self.rtcp_sr_packets = 0
        self.rtcp_rr_packets = 0
        self.rtcp_ssrcs: dict[int, int] = {}
        self.gtp_teids: dict[str, list] = {}      # TEID -> [包数, 字节数]
        self.gtp_inner_protos: Counter = Counter()
        self.gtp_merge: dict[str, GtpTeidMerge] = {}   # TEID -> 内层数据合并记录
        self.esp_spis: dict[str, list] = {}       # SPI -> [包数, 字节数]
        self.esp_spi_last: dict[str, int] = {}    # SPI -> 已见最大序列号
        self.esp_seq_regress = 0                  # 序列号未递增次数
        self.esp_regress_spis: set[str] = set()   # 出现序列号回退的 SPI
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

    def feed(self, info: PacketInfo) -> None:
        self.count += 1
        self.bytes += info.wire_len
        self.l3[info.l3] += 1
        self.l4[info.l4] += 1
        if info.tcp_flags:
            for flag in info.tcp_flags.split(","):
                self.tcp_flags[flag] += 1
        if info.dport is not None:
            self.ports[(info.l4, info.dport)] += 1
        for chunk in info.detail.get("chunks", []):
            self.sctp_chunks[chunk] += 1
        if "ppid" in info.detail:
            self.sctp_ppids[f"{info.detail['ppid']}({info.detail.get('ppid_name')})"] += 1
        if "sip_method" in info.detail:
            self.sip_methods[info.detail["sip_method"]] += 1
        if "sip_status" in info.detail:
            sc = info.detail["sip_status"]
            self.sip_status[f"{sc} ({info.detail.get('sip_status_name', '')})"] += 1
        if "rtcp_types" in info.detail:
            for rt in info.detail["rtcp_types"]:
                self.rtcp_types[rt] += 1
        if info.l4 == "RTCP":
            ssrc = info.detail.get("rtcp_ssrc")
            if ssrc is not None:
                self.rtcp_ssrcs[ssrc] = self.rtcp_ssrcs.get(ssrc, 0) + 1
            if "rtcp_ntp_ts" in info.detail:
                self.rtcp_sr_packets += 1
        if "gtp_teid" in info.detail:
            rec = self.gtp_teids.setdefault(info.detail["gtp_teid"], [0, 0])
            rec[0] += 1
            rec[1] += info.wire_len
        if "gtp_inner_proto" in info.detail:
            self.gtp_inner_protos[info.detail["gtp_inner_proto"]] += 1
        if info.gtp_seg:
            teid = info.detail.get("gtp_teid", "0x00000000")
            rec = self.gtp_merge.get(teid)
            if rec is None:
                rec = GtpTeidMerge(teid=teid)
                self.gtp_merge[teid] = rec
            rec.add(info)
        if "esp_spi" in info.detail:
            spi = info.detail["esp_spi"]
            rec = self.esp_spis.setdefault(spi, [0, 0])
            rec[0] += 1
            rec[1] += info.wire_len
            seq = info.detail.get("esp_seq", 0)
            last = self.esp_spi_last.get(spi)
            if last is not None and seq <= last:
                # ESP 序列号应单调递增, 重复或回退提示重放/乱序
                self.esp_seq_regress += 1
                self.esp_regress_spis.add(spi)
            if last is None or seq > last:
                self.esp_spi_last[spi] = seq

        if info.ts:
            if self.first_ts is None or info.ts < self.first_ts:
                self.first_ts = info.ts
            if self.last_ts is None or info.ts > self.last_ts:
                self.last_ts = info.ts

        if info.sport is not None and info.dport is not None:
            a = (info.src, info.sport)
            b = (info.dst, info.dport)
            if a > b:
                a, b = b, a
            key = (info.l4, a, b)
            rec = self.flows.get(key)
            if rec is None:
                self.flows[key] = [1, info.wire_len]
            else:
                rec[0] += 1
                rec[1] += info.wire_len

    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)


def _width(text: str) -> int:
    """按终端显示宽度计算字符串长度(中文占 2 列)。"""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
               for ch in text)


def _pad(text: str, width: int, align: str = "<") -> str:
    """按显示宽度补空格对齐。"""
    gap = max(0, width - _width(text))
    return (" " * gap + text) if align == ">" else (text + " " * gap)


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def _bar(count: int, total: int, width: int = 28) -> str:
    if total <= 0:
        return ""
    return "#" * max(0, round(count / total * width))


def _fmt_ts(ts: float, with_date: bool = False) -> str:
    if not ts:
        return "-"
    fmt = "%Y-%m-%d %H:%M:%S.%f" if with_date else "%H:%M:%S.%f"
    return datetime.fromtimestamp(ts).strftime(fmt)[:-3]   # 毫秒精度


def _print_section(title: str, rows: list[tuple[str, int]], total: int,
                   min_count: int = 1) -> None:
    if not rows:
        return
    rows = [(name, cnt) for name, cnt in rows if cnt >= min_count]
    if not rows:
        return
    name_width = max(len(r[0]) for r in rows)
    print(f"\n{title}")
    for name, cnt in rows:
        pct = cnt / total * 100 if total else 0
        print(f"  {name:<{name_width}}  {cnt:>8}  {pct:>6.2f}%  {_bar(cnt, total)}")


def _gtp_tunnel_json(rec: GtpTeidMerge, dump: Optional[str] = None,
                     dump_bytes: int = 256) -> dict:
    """GTP-U 单个 TEID 合并记录的 JSON 表示。"""
    item = {
        "teid": rec.teid,
        "packets": rec.packets,
        "payload_bytes": rec.bytes,
        "merged_bytes": len(rec.merged),
        "truncated": rec.truncated,
        "inner_protocols": dict(rec.inner_protos),
        "flows": [{"flow": label, "packets": cnt} for label, cnt in rec.flows.most_common()],
    }
    if rec.seq_first is not None:
        item.update({"seq_first": rec.seq_first, "seq_last": rec.seq_last,
                     "seq_jumps": rec.seq_jumps})
    if dump and rec.merged:
        item["payload"] = payload_block(rec.payload, dump, dump_bytes, 0)
    return item


def print_report(reader: CaptureReader, stats: Statistics,
                 dump: Optional[str] = None, dump_bytes: int = 256) -> None:
    lt = reader.linktypes[0] if reader.linktypes else -1
    line = "=" * 78
    print(line)
    print(f"文件     : {os.path.basename(reader.path)}")
    print(f"路径     : {os.path.abspath(reader.path)}")
    print(f"容器格式 : {reader.format_name}")
    print(f"链路类型 : {lt} / {LINKTYPE_NAMES.get(lt, '未知')}")
    print(f"包总数   : {stats.count}    总字节 : {_fmt_bytes(stats.bytes)}")
    dur = stats.duration()
    if stats.first_ts:
        print(f"时间范围 : {_fmt_ts(stats.first_ts, True)} ~ {_fmt_ts(stats.last_ts, True)}"
              f"   (跨度 {dur:.3f} s)")
    if dur > 0:
        print(f"平均速率 : {stats.count / dur:.1f} pkt/s, "
              f"{_fmt_bytes(stats.bytes / dur)}/s")
    print(line)

    total = stats.count or 1
    _print_section("网络层协议分布", stats.l3.most_common(), total)
    _print_section("传输层协议分布", stats.l4.most_common(), total)

    if stats.tcp_flags:
        _print_section("TCP 标志位统计", stats.tcp_flags.most_common(), total)
    if stats.sctp_chunks:
        _print_section("SCTP Chunk 统计", stats.sctp_chunks.most_common(), total)
    if stats.sctp_ppids:
        _print_section("SCTP PPID 统计", stats.sctp_ppids.most_common(), total)
    if stats.sip_methods:
        _print_section("SIP 方法统计", stats.sip_methods.most_common(), total)
    if stats.sip_status:
        _print_section("SIP 响应码统计", stats.sip_status.most_common(), total)
    if stats.rtcp_types:
        _print_section("RTCP 类型统计", stats.rtcp_types.most_common(), total)
        if stats.rtcp_ssrcs:
            rows = [(f"SSRC={ssrc:08x} packets={cnt}", cnt)
                    for ssrc, cnt in sorted(stats.rtcp_ssrcs.items(), key=lambda kv: kv[1], reverse=True)]
            print("\nRTCP SSRC 分布")
            for name, cnt in rows:
                print(f"  {name}")

    if stats.gtp_teids:
        rows = sorted(stats.gtp_teids.items(), key=lambda kv: kv[1][0], reverse=True)
        print(f"\nGTP 隧道分布 ({len(rows)} 条)")
        name_width = max(len(f"TEID={teid} packets={rec[0]} bytes={_fmt_bytes(rec[1])}")
                         for teid, rec in rows)
        for teid, rec in rows:
            name = f"TEID={teid} packets={rec[0]} bytes={_fmt_bytes(rec[1])}"
            print(f"  {name:<{name_width}}  {_bar(rec[0], total)}")
        if stats.gtp_inner_protos:
            _print_section("GTP 内层协议", stats.gtp_inner_protos.most_common(),
                           sum(stats.gtp_inner_protos.values()) or 1)

    if stats.gtp_merge:
        rows = sorted(stats.gtp_merge.items(), key=lambda kv: kv[1].packets,
                      reverse=True)
        print(f"\nGTP-U TEID 合并输出 ({len(rows)} 条隧道)")
        for teid, rec in rows:
            seq_txt = ""
            if rec.seq_first is not None:
                seq_txt = f"  seq={rec.seq_first}..{rec.seq_last}"
                if rec.seq_jumps:
                    seq_txt += f" 跳变={rec.seq_jumps}"
            print(f"  TEID={teid} packets={rec.packets} "
                  f"merged={len(rec.merged)}/{rec.bytes} B{seq_txt}")
            if rec.inner_protos:
                protos = ", ".join(f"{name}({cnt})"
                                   for name, cnt in rec.inner_protos.most_common())
                print(f"    内层协议: {protos}")
            for label, cnt in rec.flows.most_common(3):
                print(f"    流: {label} ({cnt})")
            if rec.truncated:
                print(f"    合并数据已截断, 上限 {GTP_MERGE_MAX_BYTES} B "
                      f"(共 {rec.bytes} B)")
            if dump and rec.merged:
                for line in rec.payload_lines(dump, dump_bytes):
                    print("    " + line)

    if stats.esp_spis:
        rows = sorted(stats.esp_spis.items(), key=lambda kv: kv[1][0], reverse=True)
        print(f"\nESP SPI 分布 ({len(rows)} 条)")
        name_width = max(len(f"SPI={spi} packets={rec[0]} bytes={_fmt_bytes(rec[1])}")
                         for spi, rec in rows)
        for spi, rec in rows:
            name = f"SPI={spi} packets={rec[0]} bytes={_fmt_bytes(rec[1])}"
            mark = "  疑似重放/乱序" if spi in stats.esp_regress_spis else ""
            print(f"  {name:<{name_width}}  {_bar(rec[0], total)}{mark}")
        if stats.esp_seq_regress:
            print(f"  序列号未递增 {stats.esp_seq_regress} 次, 涉及 "
                  f"{len(stats.esp_regress_spis)} 个 SPI（需结合抓包乱序判断）")

    port_rows = [(f"{proto}/dst={port}", cnt)
                 for (proto, port), cnt in stats.ports.most_common(15)]
    _print_section("目的端口 Top 15", port_rows, total)

    if stats.flows:
        rows = sorted(stats.flows.items(), key=lambda kv: kv[1][0], reverse=True)[:15]
        print("\n会话流 Top 15")
        for (proto, a, b), (cnt, nbytes) in rows:
            print(f"  {proto:<6} {a[0]}:{a[1]} <-> {b[0]}:{b[1]}"
                  f"  packets={cnt}  bytes={nbytes}")


def print_packets(packets: list[PacketInfo], dump: Optional[str] = None,
                  dump_bytes: int = 256) -> None:
    if not packets:
        print("\n没有匹配的包。")
        return
    print(f"\n逐包列表 ({len(packets)} 个包)")
    cols = [(6, ">"), (14, "<"), (22, "<"), (22, "<"), (9, "<"), (46, "<"), (6, ">")]
    names = ["#", "时间", "源地址", "目的地址", "协议", "信息", "长度"]
    header = "  ".join(_pad(n, c[0], c[1]) for n, c in zip(names, cols))
    print(header)
    print("-" * _width(header))
    for p in packets:
        proto = p.l4 if p.l4 != "-" else p.l3
        src = f"{p.src}:{p.sport}" if p.sport is not None else (p.src or "-")
        dst = f"{p.dst}:{p.dport}" if p.dport is not None else (p.dst or "-")
        info = p.summary()
        if _width(info) > 46:
            info = info[:43] + "..."
        cells = [str(p.index), _fmt_ts(p.ts), src[:22], dst[:22], proto, info,
                 str(p.wire_len)]
        print("  ".join(_pad(v, c[0], c[1]) for v, c in zip(cells, cols)))
        if dump and p.payload:
            for line in p.payload_lines(dump, dump_bytes):
                print("      " + line)


def run(args: argparse.Namespace) -> int:
    reader = CaptureReader(args.file)
    stats = Statistics()
    collected: list[PacketInfo] = []
    shown = 0
    cache = ReassemblyCache()          # 单次抓包内共享的流重组缓存
    show_list = args.verbose or bool(args.dump)

    try:
        for raw in reader.packets():
            if args.limit and stats.count >= args.limit:
                break
            info = parse_packet(raw, cache)
            cache.evict_expired(raw.ts)
            if not _match_filter(info, args.filter):
                continue
            stats.feed(info)
            if (show_list or args.json) and (args.max_lines <= 0 or shown < args.max_lines):
                collected.append(info)
                shown += 1
    finally:
        reader.close()

    if args.json:
        out = {
            "file": os.path.abspath(args.file),
            "format": reader.format_name,
            "linktype": reader.linktypes[0] if reader.linktypes else None,
            "packet_count": stats.count,
            "total_bytes": stats.bytes,
            "duration": round(stats.duration(), 6),
            "l3_protocols": dict(stats.l3),
            "l4_protocols": dict(stats.l4),
            "tcp_flags": dict(stats.tcp_flags),
            "sctp_chunks": dict(stats.sctp_chunks),
            "sctp_ppids": dict(stats.sctp_ppids),
            "top_ports": {f"{p}/{d}": c for (p, d), c in stats.ports.most_common(20)},
            "flows": [
                {"proto": k[0], "endpoint_a": f"{k[1][0]}:{k[1][1]}",
                 "endpoint_b": f"{k[2][0]}:{k[2][1]}",
                 "packets": v[0], "bytes": v[1]}
                for k, v in sorted(stats.flows.items(),
                                   key=lambda kv: kv[1][0], reverse=True)[:50]
            ],
            "packets": [p.to_json(args.dump, args.dump_bytes) for p in collected],
            "gtp_tunnels": [
                _gtp_tunnel_json(rec, args.dump, args.dump_bytes)
                for rec in sorted(stats.gtp_merge.values(),
                                  key=lambda r: r.packets, reverse=True)
            ],
        }
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    print_report(reader, stats, args.dump, args.dump_bytes)
    if show_list:
        print_packets(collected, args.dump, args.dump_bytes)
        if args.max_lines > 0 and shown >= args.max_lines:
            print(f"\n(仅显示前 {args.max_lines} 条, 可用 --max-lines 0 显示全部)")
    return 0


def _match_filter(info: PacketInfo, flt: Optional[str]) -> bool:
    if not flt:
        return True
    f = flt.strip().lower()
    l4 = info.l4.lower()
    l3 = info.l3.lower()
    aliases = {"icmpv4": "icmp", "icmpv6": "icmpv6", "ip4": "ipv4", "ip6": "ipv6",
               "arp": "arp"}
    f = aliases.get(f, f)
    if f == "icmp" and l4 in ("icmp", "icmpv6"):
        return True
    if f in ("tcp", "udp", "sctp", "sip", "http") and l4 == f:
        return True
    if f in ("rtp", "rtcp") and l4 == f:
        return True
    return f in (l4, l3)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="解析 PCAP/PCAPNG 文件, 区分 TCP / UDP / SCTP / SIP 等协议",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("file", help="pcap / pcapng 文件路径")
    p.add_argument("-v", "--verbose", action="store_true", help="输出逐包列表")
    p.add_argument("--max-lines", type=int, default=50,
                   help="逐包列表最多显示条数, 0 表示不限制 (默认 50)")
    p.add_argument("--filter", metavar="PROTO",
                   help="只统计指定协议: tcp/udp/sctp/sip/icmp/icmpv6/ipv4/ipv6/arp")
    p.add_argument("--limit", type=int, default=0,
                   help="最多处理前 N 个包 (默认 0 = 全部)")
    p.add_argument("--dump", choices=["hex", "str", "both"], metavar="MODE",
                   help="展示未解码载荷(Raw/ESP/未知应用层)及 GTP-U 按 TEID "
                        "合并内容: hex / str / both")
    p.add_argument("--dump-bytes", type=int, default=256, metavar="N",
                   help="每包 dump 的最大字节数, 0 表示全部 (默认 256)")
    p.add_argument("--json", action="store_true", help="以 JSON 格式输出")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not os.path.isfile(args.file):
        print(f"错误: 文件不存在 -> {args.file}", file=sys.stderr)
        return 2
    try:
        return run(args)
    except (ValueError, struct.error) as exc:
        import traceback as _tb
        _tb.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    import traceback as _tb
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as _e:
        _tb.print_exc(file=sys.stderr)
        raise SystemExit(1)
