# -*- coding: utf-8 -*-
"""pcap_analyzer L7 自动识别功能的单元测试"""
import os
import struct
import sys
import unittest

# Ensure the pcap_analyzer module is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from pcap_analyzer import (
    _identify_l7,
    _parse_tcp,
    _parse_udp,
    PacketInfo,
    TCP_PORT_MAP,
    UDP_PORT_MAP,
    SIP_METHODS,
)


class TestPortMaps(unittest.TestCase):
    """测试端口映射表的完整性"""

    def test_udp_port_map_has_common_protocols(self):
        """UDP 端口映射应覆盖常见协议端口"""
        expected = {
            80: "HTTP", 443: "HTTPS", 53: "DNS",
            5060: "SIP", 5004: "RTP", 5005: "RTCP",
        }
        for port, proto in expected.items():
            self.assertIn(port, UDP_PORT_MAP, f"Port {port} missing in UDP_PORT_MAP")
            self.assertEqual(UDP_PORT_MAP[port], proto)

    def test_tcp_port_map_has_common_protocols(self):
        """TCP 端口映射应覆盖常见协议端口"""
        expected = {
            80: "HTTP", 443: "HTTPS", 22: "SSH",
            5060: "SIP", 25: "SMTP", 3306: "MySQL",
        }
        for port, proto in expected.items():
            self.assertIn(port, TCP_PORT_MAP, f"Port {port} missing in TCP_PORT_MAP")
            self.assertEqual(TCP_PORT_MAP[port], proto)

    def test_sip_methods_contains_required(self):
        """SIP 方法集应包含 RFC 3261 的核心方法"""
        for method in ("INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS"):
            self.assertIn(method, SIP_METHODS)

    def test_port_map_no_overlap(self):
        """UDP 和 TCP 端口映射应保持一致的协议名（对于两者共用的端口）"""
        common_ports = set(UDP_PORT_MAP) & set(TCP_PORT_MAP)
        for port in common_ports:
            self.assertEqual(
                UDP_PORT_MAP[port], TCP_PORT_MAP[port],
                f"Mismatch for port {port}: UDP={UDP_PORT_MAP[port]} vs TCP={TCP_PORT_MAP[port]}"
            )


class TestIdentifyL7(unittest.TestCase):
    """测试 _identify_l7 函数的 L7 识别逻辑"""

    def _make_dns_query(self):
        """构造一个 DNS 查询 payload（QR=0）。含 txn_id 以符合标准 DNS 格式。"""
        txn_id = b"\x12\x34"
        flags = struct.pack("!H", 0x0100)  # QR=0
        qname = b"\x03www\x07example\x03com\x00"
        qtype = struct.pack("!HH", 1, 1)
        return txn_id + flags + qname + qtype

    def _make_dns_response(self):
        """构造一个 DNS 响应 payload（QR=1）。含 txn_id 以符合标准 DNS 格式。"""
        txn_id = b"\x12\x34"
        flags = struct.pack("!H", 0x8180)  # QR=1
        qname = b"\x03www\x07example\x03com\x00"
        qtype = struct.pack("!HH", 1, 1)
        return txn_id + flags + qname + qtype

    # ---- 端口匹配 ----

    def test_udp_port_match_http(self):
        payload = b"GET / HTTP/1.1\r\n"
        self.assertEqual(_identify_l7(payload, 80, 55000, is_udp=True), "HTTP")

    def test_udp_port_match_dns_query(self):
        payload = self._make_dns_query()
        self.assertEqual(_identify_l7(payload, 53, 55000, is_udp=True), "DNS")

    def test_udp_port_match_dns_response_via_source(self):
        """DNS 响应从服务器端口 53 到客户端"""
        payload = self._make_dns_response()
        self.assertEqual(_identify_l7(payload, 55000, 53, is_udp=True), "DNS")

    def test_udp_port_match_sip(self):
        payload = b"INVITE sip:test SIP/2.0\r\n"
        self.assertEqual(_identify_l7(payload, 5060, 5060, is_udp=True), "SIP")

    def test_udp_port_match_ntp(self):
        payload = b"\xe3\x00\x04\xfa" + b"\x00" * 40
        self.assertEqual(_identify_l7(payload, 123, 12345, is_udp=True), "NTP")

    def test_udp_port_match_stun(self):
        payload = b"\x00\x01" + b"\x00\x0c" + b"\x21\x12\xa4\x34" + b"\x00" * 8
        self.assertEqual(_identify_l7(payload, 3478, 50000, is_udp=True), "STUN")

    def test_udp_port_match_rtp(self):
        payload = b"\x80\x00" + struct.pack("!IIII", 0x12345678, 0x87654321, 0xDEADBEEF, 0xCAFEBABE)
        self.assertEqual(_identify_l7(payload, 5004, 50000, is_udp=True), "RTP")

    def test_udp_port_match_rtcp(self):
        payload = b"\x81\x00" + struct.pack("!II", 0, 0) + b"\x00" * 12
        self.assertEqual(_identify_l7(payload, 5005, 50000, is_udp=True), "RTCP")

    # TCP 端口匹配

    def test_tcp_port_match_http(self):
        payload = b"GET / HTTP/1.1\r\n"
        self.assertEqual(_identify_l7(payload, 80, 55000, is_udp=False), "HTTP")

    def test_tcp_port_match_https(self):
        payload = b"\x16\x03\x01" + b"\x00" * 10  # TLS record
        self.assertEqual(_identify_l7(payload, 443, 55000, is_udp=False), "HTTPS")

    def test_tcp_port_match_ssh(self):
        payload = b"SSH-2.0-Python\r\n"
        self.assertEqual(_identify_l7(payload, 22, 55000, is_udp=False), "SSH")

    def test_tcp_port_match_smtp(self):
        payload = b"EHLO example.com\r\n"
        self.assertEqual(_identify_l7(payload, 25, 55000, is_udp=False), "SMTP")

    def test_tcp_port_match_mysql(self):
        payload = struct.pack("!I", 0) + b"\xfb\x62\x00\x00"
        self.assertEqual(_identify_l7(payload, 3306, 55000, is_udp=False), "MySQL")

    def test_tcp_port_match_postgres(self):
        self.assertEqual(_identify_l7(b"\x00\x00\x00\x08\x04\xd2\x16\x2f", 5432, 55000, is_udp=False), "PostgreSQL")

    def test_tcp_port_match_mongodb(self):
        self.assertEqual(_identify_l7(b"\x10\x00\x00\x00", 27017, 55000, is_udp=False), "MongoDB")

    def test_tcp_port_match_http_8080(self):
        payload = b"POST /api HTTP/1.1\r\n"
        self.assertEqual(_identify_l7(payload, 8080, 55000, is_udp=False), "HTTP")

    def test_tcp_port_match_https_8443(self):
        payload = b"\x16\x03\x01" + b"\x00" * 10
        self.assertEqual(_identify_l7(payload, 8443, 55000, is_udp=False), "HTTPS")

    # ---- payload 特征识别 ----

    def test_http_get_via_payload(self):
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.assertEqual(_identify_l7(payload, 9080, 55000, is_udp=False), "HTTP")

    def test_http_post_via_payload(self):
        payload = b"POST /api/login HTTP/1.1\r\n"
        self.assertEqual(_identify_l7(payload, 9080, 55000, is_udp=False), "HTTP")

    def test_http_head_via_payload(self):
        payload = b"HEAD / HTTP/1.1\r\n"
        self.assertEqual(_identify_l7(payload, 9080, 55000, is_udp=False), "HTTP")

    def test_http_response_via_payload(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        self.assertEqual(_identify_l7(payload, 9080, 55000, is_udp=False), "HTTP")

    def test_sip_invite_via_payload(self):
        payload = b"INVITE sip:bob SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.10\r\n" \
                  b"From: <sip:alice@192.168.1.10>\r\nTo: <sip:bob@10.0.0.1>\r\n" \
                  b"Call-ID: test@sip\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        self.assertEqual(_identify_l7(payload, 9060, 55000, is_udp=True), "SIP")

    def test_sip_ack_via_payload(self):
        payload = b"ACK sip:bob SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.10\r\n" \
                  b"From: <sip:alice@192.168.1.10>\r\nTo: <sip:bob@10.0.0.1>\r\n" \
                  b"Call-ID: test@sip\r\nCSeq: 2 ACK\r\n\r\n"
        self.assertEqual(_identify_l7(payload, 9060, 55000, is_udp=True), "SIP")

    def test_sip_response_via_payload(self):
        payload = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.168.1.10\r\n" \
                  b"From: <sip:alice@192.168.1.10>;tag=a\r\n" \
                  b"To: <sip:bob@10.0.0.1>;tag=b\r\n" \
                  b"Call-ID: test@sip\r\nCSeq: 1 INVITE\r\n\r\n"
        self.assertEqual(_identify_l7(payload, 9060, 55000, is_udp=True), "SIP")

    def test_sip_bye_via_payload(self):
        payload = b"BYE sip:bob@10.0.0.1 SIP/2.0\r\n" \
                  b"Via: SIP/2.0/UDP 192.168.1.10\r\n" \
                  b"From: <sip:alice@192.168.1.10>\r\n" \
                  b"To: <sip:bob@10.0.0.1>\r\n" \
                  b"Call-ID: test@sip\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
        self.assertEqual(_identify_l7(payload, 9060, 55000, is_udp=True), "SIP")

    def test_dns_response_via_payload(self):
        payload = self._make_dns_response()
        self.assertEqual(_identify_l7(payload, 9053, 55000, is_udp=True), "DNS")

    def test_dns_tcp_response_via_payload(self):
        payload = self._make_dns_response()
        self.assertEqual(_identify_l7(payload, 9053, 55000, is_udp=False), "DNS")

    def test_dns_tcp_length_prefixed_response(self):
        """TCP DNS 带 2 字节长度前缀（RFC 1035 §4.2.2），flags 在偏移 4"""
        msg = self._make_dns_response()          # 完整 DNS 消息（含 txn_id）
        payload = struct.pack("!H", len(msg)) + msg
        # 长度前缀使 flags 后移到偏移 4，识别逻辑需兼容
        self.assertEqual(_identify_l7(payload, 9053, 55000, is_udp=False), "DNS")

    def test_dns_tcp_length_prefixed_query_not_detected(self):
        """TCP DNS 查询（QR=0）即便带长度前缀也不应通过 payload 识别"""
        msg = self._make_dns_query()
        payload = struct.pack("!H", len(msg)) + msg
        self.assertIsNone(_identify_l7(payload, 9053, 55000, is_udp=False))

    def test_empty_payload_returns_none(self):
        self.assertIsNone(_identify_l7(b"", 9999, 9999, is_udp=True))

    def test_very_short_payload_returns_none(self):
        self.assertIsNone(_identify_l7(b"AB", 9999, 9999, is_udp=True))

    def test_binary_payload_returns_none(self):
        payload = bytes(range(256)) * 2
        self.assertIsNone(_identify_l7(payload[:8], 0, 0, is_udp=True))

    def test_unknown_port_unknown_payload_returns_none(self):
        payload = b"HELLO world test"
        self.assertIsNone(_identify_l7(payload, 12345, 0, is_udp=True))

    def test_non_ascii_start_returns_none(self):
        payload = bytes([0x80, 0x01, 0x02, 0x03])
        self.assertIsNone(_identify_l7(payload, 0, 0, is_udp=True))

    def test_sip_register_via_payload(self):
        payload = b"REGISTER sip:sip.server.com SIP/2.0\r\n" \
                  b"Via: SIP/2.0/UDP 192.168.1.10\r\n" \
                  b"From: <sip:alice@192.168.1.10>\r\n" \
                  b"To: <sip:alice@192.168.1.10>\r\n" \
                  b"Call-ID: reg@sip\r\nCSeq: 1 REGISTER\r\n" \
                  b"Content-Length: 0\r\n\r\n"
        self.assertEqual(_identify_l7(payload, 9060, 55000, is_udp=True), "SIP")

    def test_sip_options_via_payload(self):
        payload = b"OPTIONS sip:monitor SIP/2.0\r\n" \
                  b"Via: SIP/2.0/UDP 192.168.1.10\r\n" \
                  b"From: <sip:admin@192.168.1.10>\r\n" \
                  b"To: <sip:monitor@10.0.0.5>\r\n" \
                  b"Call-ID: opt@sip\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        self.assertEqual(_identify_l7(payload, 9060, 55000, is_udp=True), "SIP")

    def test_port_match_priority_over_payload(self):
        """端口匹配应优先于 payload 特征识别"""
        # 端口 22 应为 SSH，即使 payload 以 GET 开头
        payload = b"GET / HTTP/1.1\r\n"
        self.assertEqual(_identify_l7(payload, 22, 55000, is_udp=False), "SSH")

    def test_sport_fallback_when_dport_unknown(self):
        """当 dport 未知时，应检查 sport"""
        payload = b"GET / HTTP/1.1\r\n"
        self.assertEqual(_identify_l7(payload, 9999, 80, is_udp=False), "HTTP")

    def test_no_port_and_no_feature_returns_none(self):
        """当端口和 payload 都无法匹配时返回 None"""
        self.assertIsNone(_identify_l7(b"\x00\x01\x02\x03", 0, 0, is_udp=True))


class TestIdentifyL7WireData(unittest.TestCase):
    """测试 _identify_l7 在不同 wire 数据构造下的识别行为"""

    def make_eth_ipv4_udp(self, sport, dport, payload):
        """构造带完整 Ether/IPv4/UDP 头的帧"""
        eth = b"\x00\x11\x22\x33\x44\x55"
        eth += b"\x66\x77\x88\x99\x00\xaa"
        eth += b"\x08\x00"
        total_len = 20 + 8 + len(payload)
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total_len, 0x1234, 0x4000, 64, 17, 0,
            bytes(int(x) for x in "192.168.1.10".split(".")),
            bytes(int(x) for x in "10.0.0.1".split(".")))
        udp_hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        return eth + ip_hdr + udp_hdr + payload

    def make_eth_ipv4_tcp(self, sport, dport, payload):
        """构造带完整 Ether/IPv4/TCP 头的帧"""
        eth = b"\x00\x11\x22\x33\x44\x55"
        eth += b"\x66\x77\x88\x99\x00\xaa"
        eth += b"\x08\x00"
        total_len = 20 + 20 + len(payload)
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total_len, 0x1234, 0x4000, 64, 6, 0,
            bytes(int(x) for x in "192.168.1.10".split(".")),
            bytes(int(x) for x in "10.0.0.1".split(".")))
        # data offset=5(20 字节) 位于高 4 位，flags 位于低 8 位
        tcp_hdr = struct.pack("!HHIIHHHH", sport, dport, 1000, 2000, (5 << 12) | 0x12, 65535, 0, 0)
        return eth + ip_hdr + tcp_hdr + payload

    # 辅助方法：从完整帧中提取 UDP/TCP payload 和端口
    @staticmethod
    def _extract_udp_fields(frame):
        """从以太网帧中提取 UDP sport, dport, payload"""
        # 跳过 Ethernet 头 (14 字节)
        eth_type = struct.unpack_from("!H", frame, 12)[0]
        if eth_type != 0x0800:
            return None, None, None
        # IPv4 头起始偏移 14
        ip_hdr_start = 14
        ihl = (frame[ip_hdr_start] & 0x0F) * 4
        proto = frame[ip_hdr_start + 9]
        if proto != 17:  # UDP
            return None, None, None
        udp_start = ip_hdr_start + ihl
        sport, dport, ulen, _ = struct.unpack_from("!HHHH", frame, udp_start)
        payload = frame[udp_start + 8:]
        return sport, dport, payload

    @staticmethod
    def _extract_tcp_fields(frame):
        """从以太网帧中提取 TCP sport, dport, payload"""
        eth_type = struct.unpack_from("!H", frame, 12)[0]
        if eth_type != 0x0800:
            return None, None, None
        ip_hdr_start = 14
        ihl = (frame[ip_hdr_start] & 0x0F) * 4
        proto = frame[ip_hdr_start + 9]
        if proto != 6:  # TCP
            return None, None, None
        tcp_start = ip_hdr_start + ihl
        sport, dport = struct.unpack_from("!HH", frame, tcp_start)
        hlen = ((frame[tcp_start + 12] >> 4) & 0x0F) * 4
        payload = frame[tcp_start + hlen:]
        return sport, dport, payload

    # ---- 通过完整 wire 帧测试 UDP L7 识别 ----

    def test_dns_udp_via_wire_frame(self):
        """DNS 响应 (QR=1) 通过 UDP 完整帧应被识别为 DNS"""
        txn_id = b"\x12\x34"
        flags = struct.pack("!H", 0x8180)  # QR=1
        qname = b"\x03www\x07example\x03com\x00"
        qtype = struct.pack("!HH", 1, 1)
        payload = txn_id + flags + qname + qtype
        frame = self.make_eth_ipv4_udp(53, 55000, payload)
        _, dport, wire_payload = self._extract_udp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=True), "DNS")

    def test_sip_udp_via_wire_frame(self):
        """SIP INVITE 通过 UDP 完整帧应被识别为 SIP"""
        payload = b"INVITE sip:bob@10.0.0.1 SIP/2.0\r\n" \
                  b"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" \
                  b"From: <sip:alice@192.168.1.10>\r\n" \
                  b"To: <sip:bob@10.0.0.1>\r\n" \
                  b"Call-ID: wire-test@sip\r\n" \
                  b"CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        frame = self.make_eth_ipv4_udp(5060, 5060, payload)
        _, dport, wire_payload = self._extract_udp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=True), "SIP")

    def test_http_get_tcp_via_wire_frame(self):
        """HTTP GET 通过 TCP 完整帧应被识别为 HTTP"""
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        frame = self.make_eth_ipv4_tcp(55000, 80, payload)
        _, dport, wire_payload = self._extract_tcp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=False), "HTTP")

    def test_sip_feature_recognition_tcp(self):
        """SIP 通过非标准端口 TCP 应通过 payload 识别"""
        payload = b"ACK sip:alice@10.0.0.5:9999 SIP/2.0\r\n" \
                  b"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" \
                  b"From: <sip:alice@192.168.1.10>\r\n" \
                  b"To: <sip:bob@10.0.0.5:9999>\r\n" \
                  b"Call-ID: feat-tcp@sip\r\n" \
                  b"CSeq: 2 ACK\r\n\r\n"
        frame = self.make_eth_ipv4_tcp(5060, 9999, payload)
        _, dport, wire_payload = self._extract_tcp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=False), "SIP")

    def test_http_response_via_payload_tcp(self):
        """HTTP 响应 (HTTP/1.1 200 OK) 通过非标准端口应通过 payload 识别"""
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n"
        frame = self.make_eth_ipv4_tcp(8081, 55001, payload)
        _, dport, wire_payload = self._extract_tcp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=False), "HTTP")

    def test_ntp_via_wire_udp(self):
        """NTP 通过 UDP 完整帧应被识别为 NTP"""
        payload = b"\xe3\x00\x04\xfa" + b"\x00" * 44
        frame = self.make_eth_ipv4_udp(12345, 123, payload)
        _, dport, wire_payload = self._extract_udp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=True), "NTP")

    def test_stun_via_wire_udp(self):
        """STUN 通过 UDP 完整帧应被识别为 STUN"""
        payload = b"\x00\x01" + b"\x00\x0c" + b"\x21\x12\xa4\x34" + b"\x00" * 8
        frame = self.make_eth_ipv4_udp(50000, 3478, payload)
        _, dport, wire_payload = self._extract_udp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=True), "STUN")

    def test_ssh_via_wire_tcp(self):
        """SSH 通过 TCP 完整帧应被识别为 SSH"""
        payload = b"SSH-2.0-Python\r\n"
        frame = self.make_eth_ipv4_tcp(50100, 22, payload)
        _, dport, wire_payload = self._extract_tcp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=False), "SSH")

    def test_mysql_via_wire_tcp(self):
        """MySQL 通过 TCP 完整帧应被识别为 MySQL"""
        payload = struct.pack("!I", 0) + b"\xfb\x62" + b"\x00\x00" + b"\x00" * 10
        frame = self.make_eth_ipv4_tcp(50200, 3306, payload)
        _, dport, wire_payload = self._extract_tcp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=False), "MySQL")

    def test_http_post_8080_via_wire_tcp(self):
        """HTTP POST 通过 TCP 8080 应被识别为 HTTP"""
        payload = b"POST /api/login HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
        frame = self.make_eth_ipv4_tcp(50400, 8080, payload)
        _, dport, wire_payload = self._extract_tcp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=False), "HTTP")

    def test_dns_response_feature_tcp(self):
        """TCP DNS 响应（带 2 字节长度前缀）通过非标准端口应通过 payload 识别"""
        msg = struct.pack("!HHHHHH", 0x5678, 0x8180, 1, 0, 0, 0) \
              + b"\x03www\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        payload = struct.pack("!H", len(msg)) + msg
        frame = self.make_eth_ipv4_tcp(49152, 55002, payload)
        _, dport, wire_payload = self._extract_tcp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=False), "DNS")

    def test_rtp_via_wire_udp(self):
        """RTP 通过 UDP 完整帧应被识别为 RTP"""
        payload = b"\x80\x00" + struct.pack("!IIII", 0x12345678, 0x87654321, 0xDEADBEEF, 0xCAFEBABE)
        frame = self.make_eth_ipv4_udp(50000, 5004, payload)
        _, dport, wire_payload = self._extract_udp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=True), "RTP")

    def test_rtcp_via_wire_udp(self):
        """RTCP 通过 UDP 完整帧应被识别为 RTCP"""
        payload = b"\x81\x00" + struct.pack("!II", 0, 0) + b"\x00" * 12
        frame = self.make_eth_ipv4_udp(50000, 5005, payload)
        _, dport, wire_payload = self._extract_udp_fields(frame)
        self.assertEqual(_identify_l7(wire_payload, dport, None, is_udp=True), "RTCP")


class TestIdentifyL7EdgeCases(unittest.TestCase):
    """边缘情况测试"""

    def test_payload_just_below_threshold(self):
        """payload < 4 字节应返回 None"""
        self.assertIsNone(_identify_l7(b"", 0, 0, is_udp=True))
        self.assertIsNone(_identify_l7(b"A", 0, 0, is_udp=True))
        self.assertIsNone(_identify_l7(b"ABC", 0, 0, is_udp=True))

    def test_payload_exactly_4_bytes(self):
        """payload = 4 字节应能进入特征识别"""
        self.assertEqual(_identify_l7(b"GET ", 9999, 9999, is_udp=True), "HTTP")

    def test_payload_with_null_byte_start(self):
        """payload 以 null 字节开头应返回 None"""
        self.assertIsNone(_identify_l7(b"\x00HELLO", 0, 0, is_udp=True))

    def test_dns_query_not_detected_by_payload(self):
        """DNS 查询 (QR=0) 不应通过 payload 特征识别"""
        flags = struct.pack("!H", 0x0100)  # QR=0
        qname = b"\x03www\x07example\x03com\x00"
        qtype = struct.pack("!HH", 1, 1)
        payload = flags + qname + qtype
        # DNS 查询的 QR=0，所以 flags & 0x8000 = 0，不应通过 payload 匹配
        self.assertIsNone(_identify_l7(payload, 9999, 9999, is_udp=True))

    def test_sip_method_without_version_not_identified(self):
        """只有方法与 URI 两段、没有 SIP/2.0 版本行时不算 SIP。"""
        self.assertIsNone(_identify_l7(b"INVITE sip:bob", 6000, 6001, is_udp=True))

    def test_dns_query_still_works_via_port(self):
        """DNS 查询虽不能通过 payload 识别，但通过端口 53 应能识别"""
        flags = struct.pack("!H", 0x0100)  # QR=0
        qname = b"\x03www\x07example\x03com\x00"
        qtype = struct.pack("!HH", 1, 1)
        payload = flags + qname + qtype
        self.assertEqual(_identify_l7(payload, 53, 55000, is_udp=True), "DNS")


class TestUdpDnsParseFailNote(unittest.TestCase):
    """测试端口为 53 但 DNS 解析失败时的 note 标记"""

    @staticmethod
    def _run(sport, dport, payload):
        udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(udp), cap_len=14 + len(udp))
        _parse_udp(udp, 0, len(udp), info)
        return info

    def test_malformed_dns_payload_marked(self):
        """payload 不足 12 字节时 DNS 解析失败，应写入失败标记"""
        info = self._run(40000, 53, b"\x12\x34\x01")
        self.assertEqual(info.l4, "UDP")
        self.assertIn("DNS 解析失败", info.note)
        self.assertIn("payload=3B", info.note)

    def test_empty_dns_payload_marked(self):
        """空 payload 发往 53 端口同样应标记为 DNS 解析失败"""
        info = self._run(40000, 53, b"")
        self.assertEqual(info.l4, "UDP")
        self.assertIn("DNS 解析失败", info.note)

    def test_valid_dns_response_not_marked(self):
        """合法 DNS 响应解析成功，l4 为 DNS 且无失败标记"""
        msg = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0) \
              + b"\x03www\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        info = self._run(53, 40000, msg)
        self.assertEqual(info.l4, "DNS")
        self.assertNotIn("解析失败", info.note)

    def test_non_dns_port_unaffected(self):
        """非 53 端口且无特征时不应出现 DNS 失败标记"""
        info = self._run(40000, 9999, b"\x12\x34\x01")
        self.assertEqual(info.l4, "UDP")
        self.assertNotIn("DNS 解析失败", info.note)

    # ---- 12 字节头部阈值边界 ----

    def test_dns_payload_11_bytes_fails(self):
        """payload 11 字节，仅差 1 字节不足 DNS 头部，应标记失败"""
        info = self._run(40000, 53, b"\x12\x34" + b"\x00" * 9)
        self.assertEqual(info.l4, "UDP")
        self.assertIn("DNS 解析失败", info.note)
        self.assertIn("payload=11B", info.note)

    def test_dns_payload_exactly_12_bytes_no_records(self):
        """payload 恰好 12 字节（qdcount=ancount=0）应解析成功，不误报失败"""
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 0, 0, 0, 0)
        info = self._run(53, 40000, hdr)
        self.assertEqual(info.l4, "DNS")
        self.assertNotIn("解析失败", info.note)
        self.assertIn("DNS response", info.note)

    def test_dns_qdcount_without_question_section(self):
        """qdcount=1 但缺少 question 段，解析器应容错返回成功"""
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        info = self._run(53, 40000, hdr)
        self.assertEqual(info.l4, "DNS")
        self.assertNotIn("解析失败", info.note)

    def test_dns_truncated_label_name(self):
        """qname 的 label 长度超出剩余字节，应容错为成功而非标记失败"""
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        info = self._run(53, 40000, hdr + b"\x20abc")  # 声明 32 字节却只有 3 字节
        self.assertEqual(info.l4, "DNS")
        self.assertNotIn("解析失败", info.note)

    # ---- 响应方向 / 端口边界 ----

    def test_dns_fail_from_source_port_53(self):
        """响应方向（sport=53）的畸形报文同样应标记失败"""
        info = self._run(53, 40000, b"\xde\xad")
        self.assertEqual(info.l4, "UDP")
        self.assertIn("DNS 解析失败", info.note)
        self.assertIn("payload=2B", info.note)

    def test_jumbogram_ulen_zero_skips_dns(self):
        """UDP 长度字段为 0（JumboGram）时提前返回，不应出现 DNS 失败标记"""
        payload = b"\x12\x34\x01"
        udp = struct.pack("!HHHH", 40000, 53, 0, 0) + payload
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(udp), cap_len=14 + len(udp))
        _parse_udp(udp, 0, len(udp), info)
        self.assertEqual(info.l4, "UDP")
        self.assertIn("JumboGram", info.note)
        self.assertNotIn("DNS 解析失败", info.note)

    # ---- 内容边界 ----

    def test_dns_nxdomain_rcode_detail(self):
        """rcode=NXDOMAIN 的响应应解析成功并记录 rcode 名"""
        qname = b"\x03www\x07example\x03com\x00"
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0)  # QR=1, rcode=3
        info = self._run(53, 40000, hdr + qname + struct.pack("!HH", 1, 1))
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_rcode_name"], "NXDOMAIN")
        self.assertNotIn("解析失败", info.note)

    def test_large_dns_payload_recognized(self):
        """超过 4096 字节的大响应应正常识别为 DNS（特征扫描只看头部）"""
        qname = b"\x03www\x07example\x03com\x00"
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        payload = hdr + qname + struct.pack("!HH", 1, 1) + b"\x00" * 5000
        info = self._run(53, 40000, payload)
        self.assertEqual(info.l4, "DNS")
        self.assertNotIn("解析失败", info.note)

    # ---- 长度字段与实际载荷不一致 ----

    def test_dns_payload_4_bytes_fails(self):
        """payload 恰好 4 字节（特征识别最小长度）仍应因不足头部而失败"""
        info = self._run(40000, 53, b"\x12\x34\x01\x00")
        self.assertEqual(info.l4, "UDP")
        self.assertIn("DNS 解析失败", info.note)
        self.assertIn("payload=4B", info.note)

    def test_dns_ulen_less_than_header(self):
        """UDP 长度字段小于头部（ulen=4）时，按实际捕获长度计算并标记失败"""
        payload = b"\x12\x34\x01"
        udp = struct.pack("!HHHH", 40000, 53, 4, 0) + payload
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(udp), cap_len=14 + len(udp))
        _parse_udp(udp, 0, len(udp), info)
        self.assertEqual(info.l4, "UDP")
        self.assertIn("DNS 解析失败", info.note)
        self.assertIn("payload=3B", info.note)

    def test_dns_ulen_exceeds_captured(self):
        """声明长度远大于实际捕获（截断抓包），失败标记应以实际字节数为准"""
        payload = b"\x12\x34\x01\x00\x05"
        udp = struct.pack("!HHHH", 40000, 53, 100, 0) + payload
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + 100, cap_len=14 + len(udp))
        _parse_udp(udp, 0, len(udp), info)
        self.assertEqual(info.l4, "UDP")
        self.assertIn("DNS 解析失败", info.note)
        self.assertIn("payload=5B", info.note)

    def test_udp_header_truncated_no_dns_mark(self):
        """UDP 头部不足 8 字节时直接判定头部截断，不应进入 DNS 流程"""
        udp = struct.pack("!HH", 40000, 53)
        info = PacketInfo(index=0, ts=0.0, wire_len=48, cap_len=48)
        _parse_udp(udp, 0, len(udp), info)
        self.assertEqual(info.l4, "UDP")
        self.assertIn("头部截断", info.note)
        self.assertNotIn("DNS", info.note)

    def test_udp_empty_payload_port_53(self):
        """UDP 头恰好 8 字节、无载荷时标记 payload=0B"""
        udp = struct.pack("!HHHH", 40000, 53, 8, 0)
        info = PacketInfo(index=0, ts=0.0, wire_len=22, cap_len=22)
        _parse_udp(udp, 0, len(udp), info)
        self.assertEqual(info.l4, "UDP")
        self.assertIn("DNS 解析失败", info.note)
        self.assertIn("payload=0B", info.note)

    # ---- 压缩指针循环防护 ----

    def test_dns_compression_pointer_self_loop_safe(self):
        """qname 为自指压缩指针时不得死循环，应容错返回

        注意：解析器传入的是完整 UDP 缓冲区，DNS 消息起始于偏移 8，
        因此 DNS 消息内的偏移 12 对应缓冲区偏移 20。
        """
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        info = self._run(53, 40000, hdr + b"\xc0\x14" + struct.pack("!HH", 1, 1))
        self.assertEqual(info.l4, "DNS")
        self.assertNotIn("解析失败", info.note)

    def test_dns_compression_pointer_mutual_loop_safe(self):
        """两个压缩指针互相指向时同样不得死循环"""
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        # 缓冲区偏移 20 指向 22，偏移 22 指回 20，形成互指环
        payload = hdr + b"\xc0\x16" + b"\xc0\x14" + struct.pack("!HH", 1, 1)
        info = self._run(53, 40000, payload)
        self.assertEqual(info.l4, "DNS")
        self.assertNotIn("解析失败", info.note)

    def test_dns_compression_pointer_valid(self):
        """合法压缩指针（指向同一消息内先前出现的标签）应能正确拼出域名"""
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        # 偏移 20 处放标签 "a"，偏移 23 的 qname 用指针指回 20
        payload = hdr + b"\x01a\x00" + b"\xc0\x14" + struct.pack("!HH", 1, 1)
        info = self._run(53, 40000, payload)
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["queries"], ["a"])
        self.assertNotIn("解析失败", info.note)

    def test_dns_query_opcode_boundary(self):
        """opcode=15（保留值）的查询应解析成功并记录 opcode 数值"""
        hdr = struct.pack("!HHHHHH", 0x4321, (15 << 11), 1, 0, 0, 0)  # QR=0, opcode=15
        payload = hdr + b"\x03www\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        info = self._run(40000, 53, payload)
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_opcode"], 15)
        self.assertNotIn("解析失败", info.note)

    # ---- 记录数量上限截断 ----

    def test_dns_qdcount_clamped_to_20(self):
        """qdcount=25 时只解析前 20 个问题，且 detail 只保留前 10 个"""
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 25, 0, 0, 0)
        question = b"\x01a\x00" + struct.pack("!HH", 1, 1)
        info = self._run(53, 40000, hdr + question * 25)
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(len(info.detail["queries"]), 10)  # 上限截断
        self.assertEqual(info.detail["dns_qdcount"], 25)   # 原始计数保留

    def test_dns_answer_rdlength_exceeds_remaining(self):
        """RDLENGTH 超出剩余字节时应跳过该记录，且不标记解析失败"""
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        question = b"\x03www\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        answer = b"\x01a\x00" + struct.pack("!HHIH", 1, 1, 0, 100)  # 声明 100 字节但无数据
        info = self._run(53, 40000, hdr + question + answer)
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["answers"], [])
        self.assertNotIn("解析失败", info.note)

    def test_dns_answer_rdlength_zero(self):
        """RDLENGTH=0 的记录应被跳过，不产生答案"""
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        question = b"\x03www\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        answer = b"\x01a\x00" + struct.pack("!HHIH", 1, 1, 0, 0)
        info = self._run(53, 40000, hdr + question + answer)
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["answers"], [])
        self.assertNotIn("解析失败", info.note)

    # ---- TCP 路径的行为 ----

    def test_tcp_dns_with_length_prefix_parsed(self):
        """TCP 上带 2 字节长度前缀的 DNS 响应应跳过前缀并完整解析"""
        msg = struct.pack("!HHHHHH", 0x1234, 0x8180, 0, 0, 0, 0)
        payload = struct.pack("!H", len(msg)) + msg
        tcp = struct.pack("!HHIIHHHH", 40000, 55000, 1, 1, (5 << 12) | 0x18, 65535, 0, 0) + payload
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(tcp), cap_len=14 + len(tcp))
        _parse_tcp(tcp, 0, len(tcp), info)
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_id"], 0x1234)
        self.assertEqual(info.detail["dns_qr"], "response")

    def test_tcp_dns_query_via_port_53_parsed(self):
        """TCP 端口 53 的裸 DNS 查询（无长度前缀、QR=0）应通过端口映射解析"""
        msg = struct.pack("!HHHHHH", 0x5678, 0x0100, 0, 0, 0, 0)  # QR=0 查询
        tcp = struct.pack("!HHIIHHHH", 40000, 53, 1, 1, (5 << 12) | 0x18, 65535, 0, 0) + msg
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(tcp), cap_len=14 + len(tcp))
        _parse_tcp(tcp, 0, len(tcp), info)
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_id"], 0x5678)
        self.assertEqual(info.detail["dns_qr"], "query")

    def test_tcp_short_payload_port_53_marked_fail(self):
        """TCP 端口 53 的畸形短报文应标记 DNS 解析失败"""
        payload = b"\x12\x34\x01"
        tcp = struct.pack("!HHIIHHHH", 40000, 53, 1, 1, (5 << 12) | 0x18, 65535, 0, 0) + payload
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(tcp), cap_len=14 + len(tcp))
        _parse_tcp(tcp, 0, len(tcp), info)
        self.assertEqual(info.l4, "TCP")
        self.assertIn("DNS 解析失败", info.note)
        self.assertIn("payload=3B", info.note)

    def test_tcp_dns_length_prefix_mismatch_not_skipped(self):
        """长度前缀与实际长度不符时不跳过前缀，且不会误判为 DNS"""
        msg = struct.pack("!HHHHHH", 0x1234, 0x8180, 0, 0, 0, 0)
        payload = struct.pack("!H", 99) + msg  # 前缀声明 99，实际 12
        tcp = struct.pack("!HHIIHHHH", 40000, 55000, 1, 1, (5 << 12) | 0x18, 65535, 0, 0) + payload
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(tcp), cap_len=14 + len(tcp))
        _parse_tcp(tcp, 0, len(tcp), info)
        self.assertEqual(info.l4, "TCP")
        self.assertNotIn("dns_id", info.detail)

    # ---- 前缀长度阈值与畸形前缀 ----

    def test_tcp_dns_payload_13_bytes_no_prefix(self):
        """payload 13 字节（不足 14，不进入前缀判断）应按偏移 2 识别并解析"""
        msg = struct.pack("!HHHHHH", 0x1111, 0x8180, 0, 0, 0, 0) + b"\x00"
        tcp = struct.pack("!HHIIHHHH", 40000, 55000, 1, 1, (5 << 12) | 0x18, 65535, 0, 0) + msg
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(tcp), cap_len=14 + len(tcp))
        _parse_tcp(tcp, 0, len(tcp), info)
        self.assertEqual(info.l4, "DNS")
        self.assertEqual(info.detail["dns_id"], 0x1111)

    def test_tcp_dns_max_prefix_value_not_skipped(self):
        """前缀为 0xFFFF（远超实际长度）时不跳过，也不误判为 DNS"""
        msg = struct.pack("!HHHHHH", 0x1234, 0x8180, 0, 0, 0, 0)
        payload = b"\xff\xff" + msg
        tcp = struct.pack("!HHIIHHHH", 40000, 55000, 1, 1, (5 << 12) | 0x18, 65535, 0, 0) + payload
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(tcp), cap_len=14 + len(tcp))
        _parse_tcp(tcp, 0, len(tcp), info)
        self.assertEqual(info.l4, "TCP")
        self.assertNotIn("dns_id", info.detail)

    def test_tcp_dns_short_prefixed_message_marked_fail(self):
        """端口 53 上带前缀但消息仅 5 字节，应标记失败且字节数含前缀"""
        payload = struct.pack("!H", 5) + b"\x12\x34\x81\x80\x00"
        tcp = struct.pack("!HHIIHHHH", 40000, 53, 1, 1, (5 << 12) | 0x18, 65535, 0, 0) + payload
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(tcp), cap_len=14 + len(tcp))
        _parse_tcp(tcp, 0, len(tcp), info)
        self.assertEqual(info.l4, "TCP")
        self.assertIn("DNS 解析失败", info.note)
        self.assertIn("payload=7B", info.note)  # 2 字节前缀 + 5 字节消息

    def test_tcp_dns_zero_length_prefix_marked_fail(self):
        """端口 53 上仅有 2 字节零前缀，应标记 payload=2B 失败"""
        payload = b"\x00\x00"
        tcp = struct.pack("!HHIIHHHH", 40000, 53, 1, 1, (5 << 12) | 0x18, 65535, 0, 0) + payload
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(tcp), cap_len=14 + len(tcp))
        _parse_tcp(tcp, 0, len(tcp), info)
        self.assertEqual(info.l4, "TCP")
        self.assertIn("DNS 解析失败", info.note)
        self.assertIn("payload=2B", info.note)

    def test_tcp_dns_prefixed_query_without_port_not_identified(self):
        """带合法前缀但 QR=0 的查询在非 53 端口无法靠特征识别（已知限制）"""
        msg = struct.pack("!HHHHHH", 0x1234, 0x0100, 0, 0, 0, 0)  # QR=0
        payload = struct.pack("!H", len(msg)) + msg
        tcp = struct.pack("!HHIIHHHH", 40000, 55000, 1, 1, (5 << 12) | 0x18, 65535, 0, 0) + payload
        info = PacketInfo(index=0, ts=0.0, wire_len=14 + len(tcp), cap_len=14 + len(tcp))
        _parse_tcp(tcp, 0, len(tcp), info)
        self.assertEqual(info.l4, "TCP")
        self.assertNotIn("dns_id", info.detail)


if __name__ == "__main__":
    unittest.main()
