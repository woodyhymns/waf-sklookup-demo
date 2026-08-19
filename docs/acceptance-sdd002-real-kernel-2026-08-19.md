# SDD-002 真实内核验收：Endpoint-aware Reservation 与 Runtime Manifest

**日期：** 2026-08-19。
**规格：** [SDD-002](specs/SDD-002-endpoint-aware-runtime-reservation.md)。
**执行脚本：** [`tests/e2e/sdd002-real-kernel.sh`](../tests/e2e/sdd002-real-kernel.sh)。
**原始证据：** [`artifacts/sdd002-real-kernel/`](../artifacts/sdd002-real-kernel/)。

## 1. 环境与隔离

验收在私有 Linux network namespace 与 private bpffs mount 中执行。该隔离是测试前提，而非便利措施：wildcard `sk_lookup` key 在其网络命名空间内可匹配任意 destination address，不能在承载控制通道的宿主网络命名空间做宽端口验证。内部 listener 为四个 `SO_REUSEPORT` worker，地址为 `127.0.0.1:18080`；Prometheus 管理端点为 `127.0.0.1:19104`；测试 ingress VIP 为 `127.0.0.2`。

| 项目 | 值 |
|---|---:|
| BPF program | C `sk_lookup`，real attach 至 private netns |
| pinned map path | `/tmp/waf-sdd002/bpffs/pin` |
| 内部 listener worker | 4 |
| baseline dynamic entry | `*:18181` |
| runtime reservation endpoint | `127.0.0.1:18080`、TLS target、`127.0.0.1:19104` |
| runtime manifest generation | `1c49403cba44654a` |

## 2. 通过项

| SDD/TDD | 实际动作 | 结果与证据 |
|---|---|---|
| T-023 / R3 | loader attach、pin、listener register 后写 manifest | 通过。`manifest-paths.txt` 指向 `/run/waf-sklookup/reservations/`，未写入 bpffs；manifest 含 `metrics-listen` source。 |
| T-021 / R2 | detached direct CLI 写入 `127.0.0.1:19104` | 通过（按预期拒绝）。错误明确为与 `metrics-listen` endpoint 冲突；`status-after-reject.json` 中 map/desired count 仍为 `1`。 |
| DFX | 读取 status | 通过。`runtime_reservation={state:"active", generation:"1c49403cba44654a", endpoint_count:3}`；`last_rejection_reason="reservation"`。 |
| T-020 / R1 | direct CLI 写入 `127.0.0.2:19104` | 通过。相同 numeric port 在不同 exact VIP 被接受，HTTP 响应确认 `local=127.0.0.2:19104`，保留原始外部 destination。 |
| 管理面隔离 | scrape `127.0.0.1:19104/metrics` | 通过。ingress VIP 写入后仍可访问 exporter，map entry 为 `2`。 |
| T-025 / R4 | 并发八个 Unix socket exact-VIP add | 通过。8/8 返回 `{"ok":true}`；loader 内 mutex 串行化 mutation，最终 `desired_count=10`、`map_count=10`、`file_map_agree=true`、`drift={put:0,delete:0}`。 |
| cleanup | 脚本 trap 停止 loader/worker、unmount bpffs | 通过。后续验收可重新 attach；无宿主网络管理通道影响。 |

## 3. 本轮发现并修复的问题

真实验收先后发现两个控制面缺口。第一，direct `add` / `bulk add` / `bulk fill` 未把 `-addr` 注册为业务参数；这会使 multi-VIP key 虽可被内部数据模型表达，却无法从主写入 API 创建。现已为三类写入口加入 `-addr`，并增加单元回归。

第二，Unix socket client 在解析 transport-only `-sock` 时，对完整 argv 运行仅允许 `sock` 的解析器，导致后续 `-addr` 被提前拒绝。现先提取 transport flag，再交由请求级 parser 解析 `tenant/site/tls/addr` 等业务参数；并发 8 路真实 socket mutation 证明修复后路径可收敛。

## 4. 结论与限制

本验收证明 endpoint-aware runtime reservation、private bpffs sidecar、multi-VIP same-port isolation、bounded rejection DFX 和生产 Unix socket serial mutation 在真实内核可运行。

> **这不是完整生产签字。**direct root CLI 仍是故障逃生入口，不应作为并发生产 mutation API；生产接入必须使用 Unix socket/control service。尚未实现的 P0 包括：manifest 的 external ownership/ACL 与 audit retention、generation/CAS desired-state transaction、pressure admission freeze、atomic BPF program/link upgrade and rollback、真实 OpenResty/Tengine TLS/WAF request path、目标硬件 CPS/p99/CPU/chaos 与灰度验证。

## 5. 可复现命令

```bash
cd waf-sklookup-demo
source "$HOME/.cargo/env"
cargo build --release --manifest-path rust/loader/Cargo.toml
sudo ART_DIR="$PWD/artifacts/sdd002-real-kernel" \
  tests/e2e/sdd002-real-kernel.sh
```

成功标志为 `SDD-002 REAL-KERNEL PASS`。运行前应确保调用者拥有 BPF attach、bpffs mount、network namespace 和 loopback 管理权限。
