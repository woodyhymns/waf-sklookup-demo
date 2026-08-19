# OpenResty/Tengine Staging 准入计划

**状态：** P0 release gate，尚未完成。
**适用：** 使用 `sk_lookup` 动态端口的 WAF node image、OpenResty/Tengine 配置与控制面。

## 1. 目标

isolated eBPF evidence 只能证明内核数据面和 loader contract。staging 必须证明真实 WAF request path 在域名、非标端口、TLS、ACL、限流、日志和 reload 语义下仍正确。任何仅有 map count、curl HTTP 或单 worker evidence 的 release 不得进入 canary。

## 2. 环境要求

| 要求 | 说明 |
|---|---|
| 节点内核与部署一致 | 记录 kernel、BTF、cgroup/LSM、bpffs、CAP_BPF/CAP_NET_ADMIN、`unprivileged_bpf_disabled`。 |
| 真实 WAF image | 使用待发布 OpenResty/Tengine build、Lua code、规则集和证书，不用 Python fixture 替代。 |
| 网络隔离 | 管理 IP/网卡/netns 与 ingress VIP 分离；静态 `reserve_endpoint` 与 runtime manifest 必须表达所有 management/fixed endpoints。 |
| 观测链路 | Prometheus scrape、structured audit、access/error log、BPF counters、reservation/status API 与 alert route 可访问。 |
| 回滚工件 | 旧 image、旧 BPF identity、pinned-map compatibility result、配置 revision 和 rollback command 预先验证。 |

## 3. 功能矩阵

| 用例 | 必须断言 |
|---|---|
| HTTP domain + dynamic non-standard port | 到达预期 WAF server block；Lua `$waf_external_port` 等于客户端原始目的端口；ACL/tenant binding 正确。 |
| HTTPS/SNI + dynamic non-standard port | SNI/certificate、TLS handshake、HTTP request policy、access log external port 一致。 |
| 同 port、不同 VIP | exact VIP A/B 路由及 binding 互不串租；loopback exporter/control endpoint 不受影响。 |
| wildcard negative | 若同 family 有 exact management endpoint，wildcard add 被拒绝且 map/desired 不变。 |
| HTTP/2、WebSocket、长连接 | upgrade/stream 建连后稳定；连接新建路径和请求路径分别采样。 |
| reload/restart | reload 不导致 dynamic map 丢失或 stale worker socket；restart 的 manifest identity、reconcile、recovery 有明确结果。 |

## 4. 性能和容量门禁

目标硬件与真实 WAF 规则下，分别测量 CPS/new SYN、keep-alive RPS、p50/p99/p999、CPU cycles/request（可用时）、CPU utilization、RSS、BPF runtime ns/SYN、map memory 和 allocation failures。每项至少交错 A/B 多轮，基线和 steered 业务请求参数一致。

| 门禁 | 阈值定义方式 |
|---|---|
| 请求路径 | steered 与 bound baseline 的中位与 tail delta 应在 SLO budget 内。 |
| 新连接路径 | CPS、BPF ns/SYN、failure ratio 与 CPU 不能超过 release budget。 |
| 容量 | 按目标 tenant/VIP 分布填充；map pressure 预警、freeze 和 headroom SLO 均可触发。 |
| 稳定性 | 持续负载窗口内无 `no_slot`、assign errno、manifest invalid、drift 或 worker black-hole。 |

## 5. 故障与止损矩阵

必须在持续流量下依次演练 worker SIGKILL、loader restart、bpffs remount、exporter failure、manifest corruption、policy reload failure、map pressure threshold、BPF upgrade prepare failure、activation health failure 和 rollback。每项应记录检测信号、自动/人工动作、恢复时间、丢失新连接数和未受影响流量。

> **停止规则：**出现 unknown assignment error、worker shard count 不收敛、manifest state 非 active、desired/map drift、reservation mutation bypass、TLS policy 不一致或任何 P0 alert 时，停止扩大流量，恢复上一 generation，并保留 artifact 供 postmortem。

## 6. canary 退出条件

只有在上述功能、性能、容量和故障矩阵全部通过且 SDD-003 rollback 已实现/演练后，才允许从节点 canary 逐级扩大。每一级至少覆盖一个完整业务峰谷周期，且必须有 owner、SLO dashboard、rollback commander 和明确 stop rule。
