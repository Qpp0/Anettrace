# ICMP 联合抓取

联合抓取支持 ICMP 和 ICMPv6 包事件。默认精简模式显示 `ICMP packet send/receive`
或 `ICMPv6 packet send/receive`；增加 `--trace-detail` 后显示设备可挂载的协议栈阶段。

在已有 root 权限的 Android shell 中运行：

```sh
# IPv4 ICMP，采集期间在另一个终端发起 ping
./anettrace --capture-trace --proto icmp --duration 10 --output /data/local/tmp/icmp.pftrace

# IPv6 ICMP
./anettrace --capture-trace --proto icmpv6 --duration 10 --output /data/local/tmp/icmpv6.pftrace

# 指定目标 IPv4 地址，查看详细协议栈阶段（替换为实际目标）
./anettrace --capture-trace --proto icmp --addr 192.0.2.1 --trace-detail \
  --duration 10 --output /data/local/tmp/icmp-detail.pftrace
```

在 Perfetto 搜索 `ICMP`，或详细模式下搜索 `icmp`、`icmpv6` 标签。
每个包事件带有源/目的地址、收发方向、`icmp_type` 和 `icmp_code`；Echo Request/Reply
还带有 `icmp_id`、`icmp_seq`。同一个被观测的 skb 使用 `packet_id` 连接各阶段，
请求和响应保持各自的包身份。ICMP 没有源/目的端口，也不创建 TCP/UDP 连接记录。

第一阶段提供包事件及路径，不进行 ping 请求/响应配对、RTT 计算或收发系统调用关联。
只在有 socket 证据时填写归属；`owner_valid=false` 表示没有确认所属应用。
事件所在的线程是探针执行时的线程，可能是网络处理线程，不等同于发起 ping 的应用。
使用 `--uid` 或 `--pid` 会严格过滤没有匹配归属的包，因此可能缺少回包；
需要观察双向 ICMP 时，使用上面的协议/IP 过滤方式。

`--traffic` 仍只接受 TCP/UDP 统计。ICMP 抓取不应组合 `--traffic` 或端口过滤。
IPv6 扩展头的解析能力沿用现有解析器；这里的 ICMPv6 支持以直接携带 ICMPv6 的 IPv6 包为范围。

Linux 上可导出 JSONL 并转换：

```sh
sudo ./src/anettrace --perfetto-events /tmp/icmp.jsonl --proto icmp
# Ctrl+C 停止后
python3 tools/anettrace_to_perfetto.py /tmp/icmp.jsonl /tmp/icmp.pftrace
```
