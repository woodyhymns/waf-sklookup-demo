# WAF 动态端口方案：可执行行动清单

配套报告：《WAF 动态非标端口 sk_lookup 方案技术评审报告》
说明：每一项都标注了代码位置，可直接建 issue 派活。

---

## P0 阻塞级（不解决不能上线）

### A1 多 worker + reuseport 分发模型定案并重做

| 项目 | 内容 |
|---|---|
| 代码位置 | `dispatch.bpf.c`（`bpf_sk_assign` flags=0）、`rust/bpf/src/lib.rs`、`rust/loader/src/openresty.rs`、`rust/loader/src/pin.rs`（`REDIR_MAX_ENTRIES=2`） |
| 现状 | sockmap 只有 2 个协议槽位而非 worker 分片；`flags=0` 导致内核仍在 reuseport 组内二次选择，实际行为与注释/恢复手册描述不一致 |
| 方案 A（推荐） | `redir_socket` 改为 worker 分片，`max_entries` = worker 上限，显式传 `BPF_SK_LOOKUP_F_NO_REUSEPORT`，自主掌控分发 |
| 方案 B | 明确依赖 reuseport 组，但必须保证槽内 fd 恒为组内存活成员，并把 rescan 改为事件驱动 |
| 验收 | 16/32 worker 下分发均衡、单 worker 崩溃不影响其余 worker 承载虚拟端口 |

### A2 引擎版本决策（`https_allow_http`）

| 项目 | 内容 |
|---|---|
| 代码位置 | `openresty/nginx.conf`、`third_party/https_allow_http/` |
| 现状 | 同端口双协议依赖 Tengine 3.1.0+ 的 `listen ... ssl https_allow_http`，stock nginx/OpenResty 无此能力 |
| 需决策 | 升级 Tengine / 自维护补丁（含 CVE 跟进成本）/ 接受控制面预分离 HTTP 与 HTTPS 端口集合 |
| 验收 | 产出书面决策，作为阶段 1 开发的前置条件 |

### A3 移除 `$waf_external_port` 的 `/proc` 线性扫描

| 项目 | 内容 |
|---|---|
| 代码位置 | `openresty/lua/waf/external_port.lua`（`resolve()` 首选 `/proc/self/net/tcp`） |
| 现状 | 每请求阻塞式打开并线性扫描全表，复杂度 O(QPS × 连接数)；实测桩掉后 p99 abs 从约 19ms 降到约 0.5ms；NAT/TIME_WAIT 下同一 `remote_ip:remote_port` 可多行匹配而取第一个，会串错端口并污染 ACL 与限流判决 |
| 优先方案 | ① `ngx.ssl.server_port()`（lua-resty-core 原生）；② connection fd 上 `getsockname()`（需查清 PR #10 被 revert 的原因）；③ BPF 侧写 LRU map，Lua FFI 直读 |
| 验收 | 请求路径零 `/proc` 访问；高并发下外部端口解析 100% 准确；重测全部延迟门禁 |

### A4 BPF 侧补齐 family / 目的地址匹配

| 项目 | 内容 |
|---|---|
| 代码位置 | `dispatch.bpf.c`（仅用 `ctx->protocol` 与 `ctx->local_port`）、`rust/loader/src/listen_fd.rs`（IPv4 only） |
| 现状 | `local_ip4`/`local_ip6`/`family` 完全未使用；端口一旦入 map，本机所有 IP（含全部 VIP 与 `127.0.0.1`）的该端口均被劫持；IPv6 SYN 会匹配成功后 `bpf_sk_assign` 一个 IPv4 socket，内核返回 `-EAFNOSUPPORT` 导致**静默丢包** |
| 方案 | map key 改为 `{family, port, addr}` 或参照 Tubular 用 LPM trie；不支持的 family 一律 `SK_PASS`；冲突检测扩展到扫 `/proc/net/tcp{,6}` 全量 LISTEN |
| 验收 | 多 VIP 隔离生效；IPv6 流量正常回落到常规 bind 查找；同机其他进程 listen 不被误伤 |

---

## P1 高危（上线前须有明确方案）

### B1 rescan 改事件驱动 + 真实健康校验

`rust/loader/src/openresty.rs`。当前 2 秒轮询 + `fstat` 比较 inode。问题：worker 死亡到 rescan 生效最长 2 秒全虚拟端口拒新连，而 nginx reload 必然换 worker；且 loader 自持 dup fd 会让 socket 结构不释放，inode 不变，**rescan 检测不到失效**。方案：nginx master 的 `ExecStartPost`/`ExecReload` 主动通知 + 用 `/proc/net/tcp` 反查 inode 是否仍在 LISTEN 集合；评估 reload 期间新旧 fd 并存以消除空窗。

### B2 G6 热更门禁在现网机型重测并定标

`docs/acceptance-prod-gng.md`、`rust/loader/src/bulk.rs`（`DEFAULT_BULK_BATCH=4096`）。现状 open 23ms / close 17ms / fail=0 都好，但期间 p99 比 1.827 > 门槛 1.10，文档标记为 parked。不能带病上线——否则运维会把变更集中到低峰批量做，退化回原痛点。需排除 `BPF_MAP_TYPE_HASH` 写入 bucket 锁与查找路径竞争、批量分片让出 CPU、以及环境噪声（G2 已证明该环境 A/B 换序可致结论翻转）。

### B3 BPF 错误码分类计数 + 同 netns 程序枚举

`dispatch.bpf.c`（`return err ? SK_DROP : SK_PASS`）、`scripts/check-install.sh`。内核允许多个 `sk_lookup` 程序共存且**最后一次选择生效**，`-EEXIST`/`-EAFNOSUPPORT`/`-ESOCKTNOSUPPORT` 对应完全不同的故障场景，当前全部合并成不可区分的黑洞。需按 errno 分别计数，并把"枚举当前 netns 已附着的 `sk_lookup` 程序"加入安装检查。

### B4 可观测性从零补齐

`rust/loader/src/metrics.rs`（仅 37 行，两个文件型指标）。见报告第八章完整目标状态。最小集合：BPF `PERCPU_ARRAY` 计数 `assign_ok` / `assign_err_{eexist,afnosupport,socktnosupport,other}` / `no_slot` / `invalid_slot` / `port_miss`；`RINGBUF` 限速采样异常四元组；只读 exporter（`BPF_OBJ_GET` + `BPF_F_RDONLY`，pin 权限 `-rw-r-----`，`chmod o+x /sys/fs/bpf`）暴露 Prometheus。

**并行必做**：梳理所有依赖 `ss`/`netstat` 的巡检脚本、容量核对、安全扫描基线、CMDB 端口台账——这些在虚拟端口上会**静默失效**。需提供等价命令并接入现有系统。

---

## P2 需补强

### C1 内核侧回到 C，用户态坚持 Rust

`rust/bpf/src/lib.rs`（`transmute(1usize)` / `transmute(86usize)` / `transmute(124usize)` 硬编码 helper ID；伪造指针字段编码 BTF；`scripts/patch-rust-btf-map-type.py` 223 行改 `.BTF` 字符串表并合并 `.maps` section；`rust-toolchain.toml` 锁 nightly）。为 30 行有效逻辑引入三个不可控失效点。用户态 `libbpf-rs` loader 质量好，继续推进。待 Aya 覆盖 `sk_lookup` + `SOCKMAP` 后再评估内核侧 Rust。

### C2 pin program + link，引入 prog tag 校验

`rust/loader/src/load.rs`、`rust/loader/src/pin.rs`。当前只 pin 两个 map，不 pin program/link，`Link` 随 loader 进程生命周期消亡；`assert_open_ports_max_entries` 只校验一个维度，**无任何机制防止新版 loader 操作旧版 BPF 程序的 map**。参照 Tubular：pin program 与 link，用 prog tag 比对拒绝版本不一致的写入，升级走 link update 实现原子替换。

### C3 配额、map 容量、压测规模三者对齐

`rust/loader/src/policy.rs`（`max_ports_per_tenant=32`、`max_ports_per_machine=128`）vs `pin.rs`（`OPEN_PORTS_MAX_ENTRIES=131072`）vs M3 的 30K/60K 压测。相差三个数量级，且 `ctl.rs` 中 bulk/fill 超 10000 需 `M3_FULL_LADDER=1`、部分路径带 `-no-file` 只改 live map，**破坏了"文件是唯一真相"契约**，`file_map_agree` 会恒为 false。另需把"memlock 恒定约 10.5MB 且与实际端口数无关、不计入 RSS"写入容量规划文档。

### C4 恢复脚本与期望态格式对齐 + fail-closed 粒度定义

`scripts/recover.sh` 仍保留 E6 之前的两字段 awk 校验器，`docs/binding.md` 已明确其与 bound 格式不兼容——这是必修的一致性 bug。另需产品层面定义 fail-closed 粒度：当前 systemd `OnFailure` + `StartLimitBurst=3` 会在 loader 三次快速失败后**停掉 OpenResty 整机等人**；而"loader 挂了但 OpenResty 仍服务真实 bind 端口"通常比整机下线更可接受。

### C5 补齐 PROXY 回退双轨

`docs/design-thin-accept-openresty.md` 已有设计，但 P1-d 验收结论为"仓库无 PROXY 回退实现 → 阻塞"。当前只有 fail-closed 而无可用降级路径，意味着内核层面出问题时唯一止损手段是关掉特性，届时相关客户端口全部不通。

---

## 阶段划分与出口标准

| 阶段 | 周期 | 内容 | 出口标准 |
|---|---|---|---|
| 0 决策门 | 1–2 周 | 内核 5.9+ 机型盘点、A2 引擎决策、A1 语义定案 | 产出"继续 / 先做 PROXY 过渡 / 放弃"的书面结论 |
| 1 数据面重做 | 3–4 周 | A1、A3、A4、B1、C2 | 单机功能与语义正确性全绿 |
| 2 可观测性 | 2–3 周 | B3、B4 | **不登录机器即可回答"某客户某端口为何不通"** |
| 3 门禁复测 | 3–4 周 | B2、按报告 7.3 条件重测、混沌演练 | 全部门禁在现网机型多 worker 下通过 |
| 4 灰度上线 | 6–8 周 | C5、单机灰度、小流量集群、逐步全量 | 现网稳定且可回滚 |

---

## 性能重测必须满足的条件（报告 7.3 摘要）

现有 G1–G10 数据**不建议对外作为"性能无损"的证据**：单 worker、rps 仅 275–346、G2 只用 3 个端口、A/B 换序结论翻转（1.2897 → 0.5628 → c=1 时 1.0303）、自研 httpbench、且全部绝对延迟被 A3 的 Lua 缺陷污染。

重测条件：现网同型号独占机器 + CPU 绑核；现网 worker 数并开 `reuseport`；用 wrk2 或 h2load 固定速率发压；map 分别 10 / 1000 / 10000 / 60000 条记录；同机真实 bind 端口作 A 腿、虚拟端口作 B 腿交替多轮取中位数；指标含建连 CPS、TLS 握手 CPS、长连吞吐、p99/p999，以及**用 `perf stat` 测每请求 CPU cycles**（对固定路径开销最敏感，不易被噪声掩盖）。
