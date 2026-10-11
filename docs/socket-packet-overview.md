# Socket 收发概览

网络事件同时显示在两个位置：原来的实际执行线程，以及 socket 下的
`TX packets` / `RX packets` 子轨道。没有方向证据的事件放在
`Unknown direction packets`，不会推断成发送或接收。

```text
demo-app
  socket 00001001
    TX packets   · send       · send
    RX packets       · receive     · receive

network-worker     · send       · send
ksoftirqd              · receive     · receive
```

概览中的每个节点对应一个已采集的包处理阶段，时间与原始事件相同。
详细模式下，同一个 skb 经过多个探针会显示多个节点；节点数不是线上包数。
TCP、UDP、ICMP 和 ICMPv6 都使用相同的显示和导航方式。

## 跳到实际线程

1. 展开目标 socket 的 `TX packets` 或 `RX packets`，点选一个节点。
2. 在详情的 **Preceding Flows** 中点击原事件名称，即可定位并选中原始线程事件；
   也可以退出搜索输入框后按 **`[`**。该表的 Thread 列显示目标线程。
3. 在原始事件上继续查看包路径、I/O 关联或系统调度。

单击概览节点本身是选中节点，随后使用上述链接或快捷键跳转。
这是 Perfetto 原生交互，无需安装插件。

概览与原事件之间使用独立的一对一导航连线；原有 `packet_id` 包路径仍然保留。
概览的 `source_tid`、`source_tgid`、`source_ts_ns`、`source_track_uuid` 指向
实际执行上下文，`navigation_id` 标识这一对节点。导航连线不是新采集的处理阶段。

## 归属与完整性

只有直接 socket 实例证据，或能够唯一关联到 socket 的 packet / flow ID，
才会生成概览节点。未知或冲突的归属继续保留在线程轨道，不按时间接近、线程名
或五元组猜测 socket。Socket 实例 ID 区分地址复用后的不同代次。

原生导出最多等待 1 秒，缓冲上限为 4096 个事件或 8 MiB，以接收较晚到达的归属
证据。达到上限会提前输出原始事件，不丢弃原始线程记录。无法在窗口内解析的事件
不生成概览。结束时的 `socket_packet_overview` 元数据记录已生成、未解析和歧义
事件数，`socket_packet_overview_buffer` 记录容量压力导致的提前输出次数。
JSONL 离线转换可以利用整份文件里的后到关联证据。
已经漏采、被过滤或被环形窗口裁剪的事件无法补回。

概览类别为 `anettrace.socket.packet`，原始类别仍为 `anettrace.packet` /
`anettrace.packet.drop`。统计时只统计原始类别，避免重复计数。
[network_chain.sql](../tools/perfetto_sql/network_chain.sql) 会排除概览副本，
查询结果仍定位到原始事件。

新增显示需要重新生成 `.pftrace`；已有 JSONL 可以重新转换。
