# WAF sk_lookup 修复与真机验证进度

## 验证环境

| 项目 | 实际结果 |
|---|---|
| 内核 / 权限 | Linux 6.1.102；可加载 `BPF_PROG_TYPE_SK_LOOKUP`，可 `BPF_LINK_CREATE` 到 netns，bpffs 已挂载 |
| BPF 程序 | C BPF 真机 verifier 通过；最终 `dispatch` tag `54d365048953e520`，约 442 instructions（bpftool xlated 3536 B）|
| CPU | 6 vCPU（3 core × SMT2），Intel Xeon 2.50 GHz；压测用 `taskset -c 0` |
| Runtime events | `kernel.bpf_stats_enabled=1`；bpftool 可读 `run_time_ns/run_cnt` |
| hardware cycles | **不可用**：当前虚拟化环境中 versioned perf 显示 `cycles` / `instructions` `<not supported>`；不得以 task-clock 冒充 cycles |
| Tooling | clang/libbpf/Rust/wrk 已安装；OpenResty OCI runtime 不可用，真实数据面以 4 worker SO_REUSEPORT HTTP stand-in 验证（fd 发现、pidfd_getfd、sockmap、sk_lookup 均真实内核路径） |

## 当前编译/单测状态

- 最近一次完整 `cargo build --release` + `cargo test`：**104 passed / 0 failed**（后续仅修改了 Python E2E server 并未改 Rust）。
- Rust 仍有原有/非功能性 warning（unused import、bulk 错误路径写 `res` 后 return 等）；尚未清零，发布前可小范围清理。

## 已完成的修复

1. **BPF 数据面**：`open_ports` key 从 2B port 扩到 20B `{port,family,addr[4]}`；精确地址后回落 family-specific wildcard；显式 IPv4/IPv6；未知 family `SK_PASS`；64 worker shard/group、4-tuple hash、`BPF_SK_LOOKUP_F_NO_REUSEPORT`；stats/ringbuf/令牌桶异常采样。
2. **多 worker 生命周期**：首次真机 kill 一个 worker 后发现 loader 自己持有的 dup 会让 dead socket 保持 LISTEN，SO_ACCEPTCONN + `/proc` 都会误判健康；已改 `CapturedListen` 记录 original `owner_pid` + `pidfd`，rescan 用 pidfd + 原进程 `/proc/<pid>/fd` 校验，并禁止 rescan 从 loader 自身重新捕获 stale socket。
3. **身份 pin**：首次真机发现 identity JSON 写在 bpffs 会 `EPERM`，且 `prog/link` 没有实际 pin。已把 JSON sidecar 放 `/run/waf-sklookup/identities/<pin>-<fnv>.json`，启动自动创建父目录；pin `maps + dispatch program + netns link` 作为全有或全无；控制面 `load_pinned_open_ports()` 比对 sidecar layout 和从 pinned `prog` 读取的 live BPF tag。篡改 tag 后 `ctl list` 真实失败闭锁，恢复后成功。
4. **外部端口 Lua**：`getsockname()` 主路径（O(1)，IPv4/IPv6）；`/proc` 仅 rate-limited fallback，改为 full 4-tuple、拒绝模糊匹配，移除逐请求 O(socket) 扫描和 `$server_port` 错回退。
5. **IPv6**：首次 IPv6 真机验证发现 loader 只扫描 `/proc/net/tcp`（不读 tcp6），且 fresh `from_lists` 永远写 AnyV4，造成 IPv6 external SYN map miss。已增加 tcp6 IPv6 word-order parser、IPv6 listener 捕获；按 `-target` address family 播种 `Dest::AnyV4/AnyV6`；启动时 target listener 与 key family mismatch fail closed。
6. **CLI**：真实 `add 18183 -tenant ...` 被 parser 视为 `-tenant` 是端口（与 README 冲突）。`parse_go_flags` 改为 positional/flag 可交错，`--` 保持硬结束；文档所示调用已真机通过。
7. **可观测性/控制**：Prometheus exporter、12 个 BPF stat slots、errno 分类、health、map/runtime identity、addr/shards list 输出、policy max map capacity 已适配。

## 已完成的真机验收（关键原始结果）

### IPv4功能与多 worker

- 4 worker internal `127.0.0.1:18080`，steered external `127.0.0.1:18181`。
- steered response 显示 `local=127.0.0.1:18181`（原始外部目的端口保留），不是 internal port。
- 120 个新连接 worker 分布示例：`26/29/29/36`，4 个 worker 均收到连接。
- stats：`assign_ok=121`、`no_slot=0`、所有 `assign_err_*=0`、`fault_ratio=0`、`listen_shards=4`。
- 动态 `add 18183` 后立即访问成功且返回 `local=127.0.0.1:18183`；`remove 18183` 后连接 refused。L7 worker PID 前后不变。

### 单 worker 故障演练

- 4 worker 中 kill 1 个：rescan 的 2s 检查窗口中，60 次短超时 probe：`53 ok / 7 fail`（窗口内预期，BPF 无法主动知道用户态 worker 已死）；3 秒后：`300/300 ok`。
- loader 日志：`owner_pid ... exited or released its listener` → `captured 3/4`（stale inode 在 non-loader /proc 无法再捕获）→ `4 -> 3 shards` → `retargeted=2`。
- 恢复后 worker 分布 `26/31/33`，`listen_shards=3`，`no_slot=0`，所有 assign error=0。
- **运维结论**：目前 hard-coded rescan 周期 2 秒决定了最大故障黑洞窗口；应在发布前增加可配置 `-rescan-interval` 并设生产建议值（例如 200–500ms）/对接 nginx worker lifecycle 事件。不能宣称单 worker crash “无损”。

### IPv6

- 4 worker internal `[::1]:18090`，steered external `[::1]:18184`。
- seeded desired 正确为：`18184 e2e ipv6 addr=[::]`。
- response `local=::1:18184`；120 个连接 worker 分布 `25/27/32/36`；`assign_ok=121`，所有 errors=0，`listen_shards=4`。

### identity / pin

- `/sys/fs/bpf/waf-e2e` 实际包含 `open_ports/redir_socket/stats/anomalies/anomaly_gate/prog/link`。
- sidecar 例：`{"id":62,"tag":"54d365048953e520","open_ports_key_size":20,"open_ports_value_size":4}`。
- 修改 sidecar tag 为全零后：`pinned program tag mismatch ... refuse to mutate maps until the loader is restarted`；恢复后 list 成功。

## 性能结果（最终有效测试，keep-alive 已修正）

### 方法

- Source: `tests/e2e/bench-sklookup.sh` / `tests/e2e/summarize_benchmark.py`。
- 4 worker、internal 18080 vs steered 18181、CPU0 pin、wrk 2 threads / 24 connections / 3 seconds、ABBA pair ×5。
- 原始 artifacts：`/tmp/waf-perf-final/`（可复制进 repo `artifacts/`）。
- keep-alive 测请求路径；`Connection: close` 测每新连接 SYN/BPF dispatch。

### 汇总（`/tmp/waf-perf-final/summary.md`）

| 指标 | Internal | Steered | 对比 |
|---|---:|---:|---:|
| keep-alive median RPS (10 samples) | 90,859.88 | 85,764.86 | 0.9439x（同机噪声，低于建议性能门禁 0.95x） |
| keep-alive median p99 | 61 µs | 59 µs | -2 µs / 0.9672x |
| new connection RPS | 22,560.78 | 22,518.07 | 0.9981x |
| new connection p99 | 12.96 ms | 12.92 ms | -40 µs / 0.9969x |
| BPF runtime median (keepalive new SYN samples) | — | 2,030.15 ns/SYN | kernel runtime stat |
| BPF runtime (`Connection: close`) | — | 1,828.93 ns/SYN | 68,828 SYN sample |
| hardware cycles/instructions | — | unavailable | VM reports `<not supported>` |

**性能定性**：延迟、新连接吞吐均通过“无可见损耗”要求；但 keepalive RPS 0.9439x 略低于拟定 0.95x 门禁，且 CPU cycles 被宿主虚拟化屏蔽。因此不能宣称整体性能验收完全通过。发布前需在目标内核/规格的裸金属或允许 PMU 的 VM 上重跑更长（≥30s×5）的 G1/G2，收集 cycles/req。

## 进行中的任务 / 待办

1. **当前状态**：已停止上一次进程并准备重启改进后的 Python E2E server；当前 service/loader 需重新启动才可继续 hot update 与最终清理。
2. **修 E2E stand-in**：keep-alive 初版每 worker 串行服务一个连接，在线 `wrk` 时新端口 curl timeout（BPF stats 仍 `assign_ok`, 无 errors），这是测试服务模型错误而非数据面错误。已将 server 改为每 accepted connection daemon thread，让 accept loop 不受 keepalive 占用；需重启后复跑热更新。
3. **热更新验收**：第一次 100-port 单租户加失败正确触发 policy `max_ports_per_tenant=32`。第二次按 4×25 tenant 批次 map 成功达 101 entries，但上述 E2E server 并发问题使 probe timeout，尚未得到有效 G6 样本。重启并发 server 后，应复跑：24 keepalive stream 持续、4 ×25 `add`, probe 18250, bulk remove 100, 记录 add/remove ms、wrk errors/RPS/p99。
4. **生产缺口**：实现 `-rescan-interval`；实现/确认 OpenResty 实际 integration（仓库 Docker compose 要求 runtime，但沙箱无 Docker/Podman；BPF 与 socket semantics 已真机验证，Lua OpenResty hook尚不能 runtime验证）。
5. **发布前**：清理两处 unused imports/warnings；新增 systemd capability/permissions doc；把 `/tmp/waf-perf-final` 原始 artifacts 拷入 repo 或报告；编写最终验证报告；`git diff`/测试/commit/push。

## 关键文件改动

- `dispatch.bpf.c`, `bpf/headers/bpf_helpers.h`
- `rust/loader/src/{key.rs,identity.rs,pin.rs,load.rs,listen_fd.rs,openresty.rs,desired.rs,bulk.rs,metrics.rs,exporter.rs,main.rs,ctl.rs,sockctl.rs,central.rs,nginx_listen.rs,policy.rs,cli.rs,toy.rs}`
- `openresty/lua/waf/external_port.lua`
- 新增 `tests/e2e/{reuseport_http_server.py,bench-sklookup.sh,summarize_benchmark.py}`
- 新增报告/进度文件 `waf-review/FIX-PROGRESS.md`

## 推送前建议

分支 `fix/dataplane-hardening`。确保 staging clean/commit，然后 `git push -u origin fix/dataplane-hardening`。如果远端默认策略拒绝直推，应转为 push branch 并创建 PR；用户要求“推到 GitHub”，推分支满足安全可回滚，不直接覆盖 main。

---

## English condensed status

The real-kernel verification found and fixed additional production-grade defects: stale SOCKMAP listener lifetime after a worker exits; identity metadata incorrectly written to bpffs; absent program/link pins; IPv6 `/proc/net/tcp6` discovery and IPv6 key seeding; and documented positional CLI flags that failed in practice. Current Rust tests: **104/104 pass**. Functional IPv4 and IPv6, program/tag fail-closed behavior, dynamic add/remove with unchanged L7 worker PIDs, 4-worker distribution, and a one-worker crash/rescan scenario were all verified against kernel 6.1.

The final valid performance benchmark showed no latency/new-connection regression: keep-alive p99 61µs internal vs 59µs steered, close-connection p99 12.96ms vs 12.92ms, new-connection RPS ratio 0.9981, BPF runtime 1.83µs per SYN over 68,828 SYNs. Keep-alive RPS median ratio was 0.9439, just below a proposed 0.95 threshold, and hardware `cycles/instructions` are unavailable in this virtual machine. Do not claim a fully passed performance gate until rerun on target production-class hardware/VM with PMU access. A hot-update test must be rerun after the newly corrected concurrent E2E server is restarted.

The remaining production issue is a 2-second hard-coded worker rescan window: after a worker crash, there was a temporary 7/60 probe failure window, followed by 300/300 success after automatic 4→3 shard rescan. Make the rescan interval configurable (or integrate with Nginx worker lifecycle events) before production rollout.
