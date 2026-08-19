# DFX 生产发布门禁

**状态：** Required for every release candidate.
**适用范围：** WAF dynamic-port loader、BPF object、control plane、OpenResty/Tengine integration、systemd deployment。
**原则：** 任何 gate 未通过只能进入明确标注的实验/灰度状态，不能以“demo 可用”替代生产签字。

## 1. Gate 总览

| DFX 维度 | 必须证明的属性 | 阻断条件 | 证据位置 |
|---|---|---|---|
| **Design** | 有 SDD、ADR、范围、风险、回滚和兼容性结论 | 需求直接改 BPF/控制面而无规格与架构签字 | `docs/specs/`、`docs/architecture/` |
| **Functional correctness** | TCP family/address/port 匹配、IPv4/IPv6、exact/wildcard、租户绑定、reconcile、rollback | 任何 P0 测试缺失或失败 | Rust unit/integration + real-kernel record |
| **Reliability** | loader crash、worker restart、link/map pin、map wipe、ctl loss、systemd restart、rollback 可演练 | 新连接黑洞无上界或无 detection/rollback | chaos script、runbook、metrics |
| **Performance** | 分离 SYN path 与 keep-alive path；测 p50/p99/RPS/CPS/CPU/BPF runtime | 目标规格 host 无数据，或回归超过批准预算 | `tests/e2e/` raw artifact |
| **Capacity** | map pressure、memlock、port quota、30K/60K/目标规模、mutation 时延 | capacity 未建模或接近 threshold 无告警 | `artifacts/`、capacity report |
| **Observability** | metrics、status、audit、anomaly、readiness、alert/runbook 可关联 generation | 故障无法通过 reason/metric 定位 | Prometheus snapshot、runbook drill |
| **Security** | 最小 capability、loopback/认证管理面、reservation、policy/audit、输入校验 | wildcard 可能接管管理端口；越权控制 map | security test 与 deployment review |
| **Serviceability** | operator 能 list binding、查冲突、dry-run、冻结、恢复和导出支持包 | 依赖人工 `bpftool` 猜测或不可复现手工步骤 | CLI test、recovery drill |

## 2. 强制上线前门槛

### 2.1 数据面可靠性

1. Pinned program、link、maps、ABI manifest 需匹配；版本不匹配时 mutation fail closed，但既有安全转发不得被无意断开。
2. 任何 worker 失效的服务影响必须可量化：检测时间、失效 shard 比例、fallback 行为、恢复时间均有指标和结果。
3. `SK_DROP` 只可用于已确认属于 WAF binding 而无法安全交付的情况；reason、counter 与 anomaly 必须完整。
4. 租户/端口变更需具备可审计 mutation id、preflight、commit 结果与 rollback 路径。

### 2.2 管理面与安全

1. metrics、ctl、SSH/host agent、health check 和 internal target 必须位于 reservation policy 或独立 management namespace/interface。
2. exporter 默认仅绑定 loopback；任何非 loopback 暴露需 TLS、认证、网络 ACL 及安全评审。
3. 每项 mutation 检查 tenant/site、deny、privileged ports、quota、map capacity、reservation、overlap 和 BPF identity。
4. metrics 不得以 customer port、source IP、tenant 等无边界维度创建 Prometheus labels。

### 2.3 性能与容量

| 指标 | 最低证据 | 发布建议 |
|---|---|---|
| 新建连接 p99 / CPS | target host、与 direct listener 交错 A/B、稳定多轮 | 相比 baseline 的预算由 SDD 声明；不得以单次平均值签字。 |
| keep-alive p99 / RPS | target host、固定并发、顺序随机化 | `sk_lookup` 不应进入已建立连接路径；任何差异必须解释。 |
| BPF runtime / SYN | `bpftool prog profile` 或 runtime stats；硬件 PMU 可用时补 cycles | 建立相对基线，不用 VM 噪声冒充无损。 |
| map pressure | current/max/headroom、warn/critical/freeze policy | production soft warn 建议 70%，critical 85%，自动 freeze 需独立演练。 |
| bulk mutation | 100、30K、60K 和目标批量；流量同时持续 | 无 reload；错误、p99、CPS 与 rollback 均记录。 |

## 3. 测试分层与停止规则

| 层级 | 运行时机 | 目标 | 停止规则 |
|---|---|---|---|
| L0 — static | 每次改动 | format、compile、BPF verifier、ABI layout、文档链接 | 任一失败阻断。 |
| L1 — unit / property | 每次改动 | parser、policy、reservation、quota、key encoding、metrics snapshot | 新分支未先写 failing test 不进入实现。 |
| L2 — isolated real kernel | 每次 BPF/control-plane 改动 | attach、IPv4/IPv6、worker shard、fault、30K/60K、cleanup | 不允许在 host management namespace 跑 wildcard capacity range。 |
| L3 — WAF integration | 每次 release candidate | OpenResty/Tengine、TLS、Lua external port、WAF policy、body/HAH | 任意协议/策略失配阻断。 |
| L4 — target-host load / chaos | 灰度前 | real traffic mix、CPS、keepalive、restart、rollback、map pressure | SLO/错误预算超限自动停止扩量。 |
| L5 — canary | 发布 | 单机/单 VIP/小租户、观测完整、可快速退回 fallback | 缺 telemetry 或 rollback 不可用则停止。 |

## 4. DFX 最小指标合同

所有 release 需要至少包含以下稳定 metric 名称或兼容 alias：

```text
waf_sklookup_open_ports_entries
waf_sklookup_open_ports_max_entries
waf_sklookup_open_ports_pressure_ratio
waf_sklookup_open_ports_headroom_entries
waf_sklookup_assign_ok_total
waf_sklookup_port_miss_total
waf_sklookup_no_slot_total
waf_sklookup_assign_err_*_total
waf_sklookup_shard_fallback_total
waf_sklookup_control_reject_total{reason="bounded"}
waf_sklookup_reconcile_generation
waf_sklookup_reconcile_last_success_unixtime
waf_sklookup_anomaly_dropped_total
waf_sklookup_ready
```

高基数细节（完整 port、tenant、source address）必须保留在受控 audit/status 支持包，而非 Prometheus label。每个告警规则应链接到一个 runbook；每个 runbook 应包含“确认 scope → 保护现有流量 → 查看 generation/map/link → 修复/rollback → 验证”的操作步骤。

## 5. 持续架构工作流

每一个能力变化按以下状态推进：

```text
Problem statement → SDD → ADR/risk review → failing TDD test
→ implementation → L0/L1 → L2 evidence → DFX update
→ target-host gate → canary decision → release record
```

`docs/specs/` 是需求和可测试验收的唯一来源；`docs/architecture/` 记录不可逆或跨组件决策；`docs/dfx/` 记录上线门禁；`artifacts/` 保存不可伪造的原始命令输出。任何跳过的 gate 必须写出 owner、风险、到期日和 rollback 方案。
