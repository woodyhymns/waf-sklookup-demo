# P1 TLS 验收清单（草稿）/ P1 TLS Acceptance Checklist (Draft)

- **里程碑**: Notion productization **P1**（HTTPS on steered ports + header policy + 同口双协议）
- **状态**: **DRAFT — awaiting Repo P1 PR** · 勿在本草稿上跑完整 TLS 验收
- **基线**: OpenResty **1.19.3.2**（`nginx version: openresty/1.19.3.2`）；生产路径可含 Tengine **`https_allow_http`**
- **依赖**: M1 HTTP 接线已 PASS（`docs/acceptance-m1.md`）；P1 在此之上加 TLS / 外泄策略 / 同口语义
- **执行人**: Test（QA）— Repo PR 就绪后再勾选
- **变量约定**: **Host = 名字**；**`$waf_external_port` = 接入口 / ingress**；**禁止**用 `$server_port` 当业务外口

> Do **not** treat this file as executed evidence. Fill PASS/FAIL only after Repo lands P1 TLS + probe flag.

## 架构注意（Alex / 生产）

生产 Tengine 有 **`https_allow_http`**：**同一外口既可 HTTP 又可 HTTPS**。不要把用例写成必须拆成「HTTP 专口 / HTTPS 专口 8443」。

- 端口号示例（`18081`、`8443`、非标口）只表示「某一个 steered 外口」，**不**表示 HTTPS-only 专口架构。
- **完整同口双协议**依赖魔改 / Tengine `https_allow_http`（或等价）。
- **Stock OpenResty 1.19.3.2** 若无该指令：下列「同口 http+https」项标 **BLOCKED** 或只做 **模拟边界**，不得假装生产行为已在 stock 上证明。
- TLS **终止在 OpenResty/引擎**（非外部 LB 代终结冒充验收）。

### Stock 模拟边界（无 `https_allow_http` 时）

| 可证明 | 不可假装已证明 |
|--------|----------------|
| sk_lookup 外口 → 固定内听；TLS 在引擎终结（若 PR 提供 TLS listen） | 同一 `PORT` 上 cleartext HTTP 与 TLS 同时被同一 `listen` 接纳 |
| 默认不回 `X-Waf-External-Port`；probe 打开可验 `$waf_external_port` | 与现网 Tengine 完全一致的同口分流语义 |
| 日志/内网仍可见接入口 | — |
| 若仅有 stock 回退：单独 TLS listen（例内听 `:8443 ssl`）steer 到外口 | 把「8443=HTTPS-only」写成产品架构 |

## 环境约束（硬性）

| 项 | 要求 | 实测 / 备注 |
|----|------|-------------|
| OpenResty | **1.19.3.2** 基线；写明是否含 Tengine/`https_allow_http` | ☐ `openresty -v` |
| 内核 | ≥5.9，`sk_lookup` | ☐ |
| 内听 | **仅**固定内听（例 `127.0.0.1:8080` 或 PR 约定 dual-protocol listen）；外口经 sk_lookup | ☐ `ss -lntp` |
| 外口示例 | steered 口（含非标）；可用 `18081` / `8443` 等数字，**非**专口架构暗示 | ☐ |
| 生产默认 | **不外泄** `X-Waf-External-Port`（或同类）到外部响应 | ☐ |
| 探针 | **probe flag ON** 时可验证 `$waf_external_port`（头 / body / log） | ☐ flag 名见下 |

### Probe flag（名待 Repo 确认）

Repo 尚未最终命名时，清单使用占位 **`probe flag`**。建议候选：

| 候选 | 形态 | 备注 |
|------|------|------|
| `WAF_EXTERNAL_PORT_PROBE` | 环境变量 / `env` | 推荐默认名 |
| `waf_external_port_probe` | nginx/`set`/`map` 变量 | 配置侧开关 |
| `--probe-external-port` | loader / 进程 CLI | 若由 loader 注入 |
| 仅内网 location / 专用 path | 配置 | 亦可，文档写清 |

**约定**:

- **生产默认 OFF**: 外部 HTTP/HTTPS 响应 **不得**出现 `X-Waf-External-Port`（及同类调试头）。
- **probe ON**: 允许头或 body 或 access/Lua 日志暴露 `$waf_external_port`，供 Test 断言 = 客户目的端口 ≠ 内听 / `$server_port`。

## 核心验收（P1 must-pass）

| # | 项 | 结果 | 证据（命令 / 日志摘录） |
|---|----|------|------------------------|
| P1-TLS-1 | **仅内听 + sk_lookup** — `ss -lntp` 仅见固定内听；steered 外口无 userspace `LISTEN` | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-2 | **外口 HTTP** — `curl http://127.0.0.1:<PORT>/` 进入 OpenResty（非玩具文案） | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-3 | **外口 HTTPS** — 对**同一 `<PORT>`**（生产语义）或 PR 文档约定口 `curl -vk https://…` 握手成功；证书来自 OpenResty 1.19.3.2 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-4 | **同口双协议（生产）** — P1-TLS-2 与 P1-TLS-3 在**同一外口**均 PASS（`https_allow_http`） | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | stock 无指令 → **BLOCKED** + 模拟边界 |
| P1-TLS-5 | **SNI / ALPN / 证书观感** — 至少：握手成功 + 证书归属引擎；与直连旧架构观感一致或文档说明差异 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-6 | **默认不外泄** — probe OFF 时外部响应 **无** `X-Waf-External-Port`（或同类） | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-7 | **probe ON 可验证** — 打开 `probe flag` 后头/body/log 可见 `$waf_external_port` = 目的端口，且 ≠ `$server_port`/内听 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-8 | **负向 map 删除** — `close-port` / `bpftool map delete` 后该口 HTTP **与** HTTPS 均失败；邻口仍可用 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-9 | **语义** — Host=名；`$waf_external_port`=ingress；业务不读 `$server_port` 当外口 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-10 | **版本备注** — OpenResty **1.19.3.2**（+ 是否含 `https_allow_http`）写入结论栏 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |

## 建议 curl / openssl 命令（Repo PR 就绪后）

```bash
PORT=<steered_external_port>   # e.g. 18081 or 8443 as a NUMBER — not "HTTPS-only architecture"
HOST=127.0.0.1

openresty -v 2>&1   # expect: nginx version: openresty/1.19.3.2

# P1-TLS-1 bind
ss -lntp | rg -E ":(8080|${PORT})\\b" || true

# P1-TLS-2 / P1-TLS-6 — HTTP, probe OFF (no leak)
curl -sS -D- "http://${HOST}:${PORT}/" | tee /tmp/p1-http.txt
rg -i 'X-Waf-External-Port' /tmp/p1-http.txt && echo 'FAIL leak' || echo 'PASS no leak'

# P1-TLS-3 / P1-TLS-5 — HTTPS on same PORT (prod) or PR fallback port
curl -vk --max-time 5 "https://${HOST}:${PORT}/" -o /tmp/p1-body.txt -D /tmp/p1-hdr.txt
# SNI / ALPN:
openssl s_client -connect ${HOST}:${PORT} -servername <SNI_HOST> -alpn h2,http/1.1 </dev/null 2>&1 \
  | rg -i 'subject|issuer|alpn|protocol'

# P1-TLS-7 — probe ON（flag 名以 Repo 为准；下例为建议名）
WAF_EXTERNAL_PORT_PROBE=1 ./run-openresty-demo.sh start   # or PR-documented switch
curl -vk "https://${HOST}:${PORT}/" -D- | rg -i 'X-Waf-External-Port|waf_external_port|'"${PORT}"

# P1-TLS-8 — negative
./run-openresty-demo.sh close-port "$PORT"
curl -sS --max-time 3 "http://${HOST}:${PORT}/"    ; echo http_exit:$?
curl -vk --max-time 3 "https://${HOST}:${PORT}/"   ; echo https_exit:$?
curl -vk "https://${HOST}:<neighbor_port>/"        # still OK
```

## 证据槽（执行时粘贴）

| 槽 | 内容 |
|----|------|
| OpenResty `-v` / `https_allow_http` 有无 | |
| `ss -lntp` 摘录 | |
| 同口（或 fallback）`curl` HTTP 摘录 | |
| `curl -vk` HTTPS 握手 / 证书 Subject / ALPN | |
| 默认响应头（证明无外泄） | |
| probe ON 证据（头/body/log） | |
| close-port 后 HTTP+HTTPS 失败 + 邻口成功 | |
| 实际 `probe flag` 名（Repo） | |

## Pass/Fail 总表

| 项 | PASS | FAIL | BLOCKED | N/A |
|----|------|------|---------|-----|
| P1-TLS-1 仅内听 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-2 外口 HTTP | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-3 外口 HTTPS | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-4 同口双协议 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-5 SNI/ALPN/证书 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-6 默认不外泄 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-7 probe 可验证 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-8 map 删除负向 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-9 Host / `$waf_external_port` | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-10 OpenResty 1.19.3.2 | ☐ | ☐ | ☐ | ☐ |

## 结论栏（Repo P1 PR 后填写 — 现在留空）

- **总体**: ☐ PASS · ☐ FAIL · ☐ BLOCKED · ☑ DRAFT (not run)
- **PR**: _TBD_
- **OpenResty 版本字符串**: _TBD — must be 1.19.3.2_
- **`https_allow_http`**: ☐ 有 · ☐ 无（stock 模拟边界）· ☐ N/A
- **TLS / 外口**: _TBD (port numbers only; same-port preferred)_
- **probe flag 实名**: _TBD (suggest `WAF_EXTERNAL_PORT_PROBE`)_
- **报告时间 (Asia/Shanghai)**: _TBD_
- **阻塞 / 交还 Repo**: 等待 P1 PR（dual-protocol listen/cert/SNI、默认藏头、probe 开关、stock gap 说明）

---
*清单作者: Test · P1 productization draft · 对齐 Alex 同口 HTTP/HTTPS · 不对齐前不执行完整 TLS*
*HTTP M1 自动化见 `scripts/accept-m1.sh`；TLS accept 脚本待 P1 PR 后再加*
*Related skeleton: `docs/repro.md` §C*
