# PCAP 协议分析器

纯标准库实现的 pcap/pcapng 解析与协议统计工具，无第三方依赖（Python 3.8+）。

## 功能概览

| 层次 | 能力 |
|---|---|
| 容器 | pcap（大小端自动识别）、pcapng、链路类型 EN10MB |
| L2/L3 | Ethernet、ARP、IPv4、IPv6（含扩展头链、分片重组） |
| L4 | TCP、UDP、SCTP、ESP（仅头）、NAT-T（RFC 3948） |
| 隧道 | GTP-U（G-PDU 内层拆解、按 TEID 合并输出）、GTPv2-C |
| 重组 | TCP DNS 流重组（2 字节长度前缀）、IPv4/IPv6 分片重组 |
| L7 | 端口映射优先 + 载荷特征兜底（HTTP/SIP/DNS/RTP/RTCP 等） |
| 输出 | 统计报告、逐包列表、JSON、未解码载荷 dump、GTP-U 合并 dump |

## 快速开始

```powershell
# 统计报告
python pcap_analyzer.py test\pcaps\dns_test.pcap

# 逐包列表 + 只看 TCP
python pcap_analyzer.py xxx.pcap -v --filter tcp

# 展示未解码载荷（ESP 密文、Raw、未知应用层）与 GTP-U 按 TEID 合并内容
python pcap_analyzer.py test\pcaps\gtp_ipv6_frag_test.pcap --dump both --dump-bytes 64

# JSON 输出
python pcap_analyzer.py xxx.pcap --json > out.json
```

## 参数

| 参数 | 说明 |
|---|---|
| `file` | pcap / pcapng 路径 |
| `-v, --verbose` | 输出逐包列表 |
| `--max-lines N` | 逐包列表上限，`0` 不限（默认 50） |
| `--filter PROTO` | 只统计指定协议：tcp/udp/sctp/sip/http/icmp/icmpv6/ipv4/ipv6/arp |
| `--limit N` | 只处理前 N 个包（默认 0 = 全部） |
| `--dump MODE` | 载荷展示：`hex` / `str` / `both` |
| `--dump-bytes N` | 每条载荷最多显示 N 字节，`0` 表示全部（默认 256） |
| `--json` | 输出 JSON |

## 输出说明

**dump 格式**：hex 行是 `偏移  16 字节(定宽 47 列)  |ASCII|`，偏移为小写十六进制、最少 4 位；
str 模式每行 64 个可打印字符（不可打印替换为 `.`）；截断时最后一行提示剩余字节数。

**JSON 顶层字段**：`file/format/linktype/packet_count/total_bytes/duration/l3_protocols/l4_protocols/
tcp_flags/sctp_chunks/sctp_ppids/top_ports/flows/packets/gtp_tunnels`。
`packets` 每项含 `l3/l4/src/dst/ports/...`；带 `--dump` 时附 `payload`（`offset/total/shown/hex/text`）。
`gtp_tunnels` 每项含 `teid/packets/payload_bytes/merged_bytes/truncated/inner_protocols/flows/seq_*`。

## 测试

```powershell
python test\scripts\run_all.py                  # 一键回归(498 例, 约 13s)
python test\scripts\run_all.py --mutation dump  # 追加载荷展示组变异扫描
python test\scripts\run_all.py --mutation core  # 追加 GTP/ESP/L7/重组组(约 3 分钟)
python test\scripts\run_all.py --mutation all   # 两组都跑
```

用例分布：`test_dump` 123、`test_esp` 41、`test_gtp` 82、`test_l7_identify` 95、
`test_reassembly` 54、`test_resources` 11、`test_mutation_tool` 92。

## 目录结构

```
pcap_analyzer.py               主程序(解析 + 统计 + 报告 + CLI)
test/scripts/run_all.py        一键回归入口
test/scripts/test_*.py         单元测试(内存构造帧, 不读磁盘 pcap)
test/scripts/make_*.py         数据生成脚本, 见下方说明
test/scripts/mutation_dump.py  变异测试工具
test/pcaps/*.pcap              演示/夹具数据
pcap-test-summary/             测试总结报告(HTML)
```

`make_*.py` 分两类：`make_dns_test / make_icmp_arp_ipv6_test / make_rtp_rtcp_test / make_sctp_test /
make_tcp_test / make_dns_tcp_reasm_test / make_gtp_ipv6_frag_test` 生成 `test/pcaps` 下的演示文件；
`make_sip_test / make_sdp_test / make_sip_tcp_test / make_l7_test / make_app_test` 属于临时演示，
输出到 `%TEMP%\pcap_analyzer_test`，不参与回归。

**单元测试不依赖 `test/pcaps`**：所有用例在内存中构造帧，`pcaps` 仅用于手工演示与报告截图。

## 变异测试工具

```powershell
python test\scripts\mutation_dump.py --list                 # 列出 dump 组 30 个变异体
python test\scripts\mutation_dump.py --group core           # 39 个变异体(GTP/ESP/L7/重组)
python test\scripts\mutation_dump.py --only M05,M17 --verbose
python test\scripts\mutation_dump.py --target pcap_analyzer.py `
    --tests test_gtp,test_esp --spec my_mutants.json          # 自定义目标与清单
```

外部清单为 JSON 数组，每项 `id/desc/old/new`，可选 `equivalent`（真值即视为等价变异）。
工具会在跑基线前校验：替换点在源码中恰好出现 1 次、编号唯一、`old != new`。

判定：非等价变异被用例捕获记为「杀死」；等价变异存活记为「等价存活」（不计入遗漏）；
非等价未被捕获记为「遗漏」。退出码 `0` 无问题、`1` 有问题、`2` 基线用例失败。

当前记录：dump 组 30 个变异体（29 杀 + 1 等价）、core 组 39 个（37 杀 + 2 等价），得分均 100%。
等价变异为 `M30`（`len(shown) < len(data)` 改 `!=`，前缀关系下恒等价）、`R05`（`put_first` 冲突与
`put` 内部重建路径行为一致）、`R07`（`delivered` 的 32 位掩码在 `_seq_delta` 内已完成）。

## 已知限制

- **ESP 只解析头**：SPI 与序列号可读；Padding / Next Header / ICV 位于加密域内，密文按原样以
  dump 展示，需密钥解密后才能解读。NAT-T 的 Keepalive / IKE(non-ESP marker) / ESP 三态可区分。
- **不做通用 TCP 全流重组**：仅针对 DNS 的 2 字节长度前缀流；其他应用层按包级特征识别。
- **资源上限**：流数、单流字节数、空闲超时受配置常量约束，超限流会被淘汰并在报告中记入资源统计。
