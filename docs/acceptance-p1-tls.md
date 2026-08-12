# P1 验收清单：TLS + 藏头（同口 HTTP/HTTPS）

- **里程碑**: [可执行里程碑：sk_lookup → OpenResty WAF](https://app.notion.com/p/3ba6e599de1981b292abfec7ccd84417) · 产品化 P1
- **基线**: OpenResty / 引擎路径对齐 **1.19.3.2** API；外口经 `sk_lookup` → 固定内听
- **状态**: **草稿** — 待 Repo P1 PR 后由 Test 实测填表；**不 merge**
- **变量约定**: **Host = 名字**；**`$waf_external_port` = 接入口**；禁止用 `$server_port` 当业务外口

## 架构注意（Alex / 生产）

生产 Tengine 有 **`https_allow_http`**：**同一外口既可 HTTP 又可 HTTPS**，不要把用例写成必须拆成「HTTP 专口 8080 / HTTPS 专口 8443」。

- 端口号示例（如 `8443`、`18081`）只表示「某一个外口」，**不**表示 HTTPS-only 专口架构。
- **完整同口双协议**依赖魔改 / Tengine `https_allow_http`（或等价）。
- **Stock OpenResty 1.19.3.2** 若无该指令：下列「同口 http+https」项标 **BLOCKED** 或只做 **模拟边界**（见下），不得假装生产行为已在 stock 上证明。

### Stock 模拟边界（无 `https_allow_http` 时）

| 可证明 | 不可假装已证明 |
|--------|----------------|
| sk_lookup 外口 → 固定内听；TLS 在引擎终结（若 PR 提供 TLS listen） | 同一 `PORT` 上 cleartext HTTP 与 TLS 同时被同一 `listen` 接纳 |
| 默认不回 `X-Waf-External-Port`；probe 打开可验 `$waf_external_port` | 与现网 Tengine 完全一致的同口分流语义 |
| 日志/内网仍可见接入口 | — |

## 环境

| 项 | 要求 | 实测 |
|----|------|------|
| 引擎 | 1.19.3.2 路径；若含 Tengine/`https_allow_http` 写明构建 | |
| 内核 | sk_lookup available | |
| 证书 | 测试用 cert（自签可）；SNI 用例写清 `-servername` | |
| Probe flag | Repo 命名（建议占位 `WAF_EXTERNAL_PORT_PROBE=1` / nginx 变量 / 仅内网 location） | |

## 核心用例（可勾选）

| # | 项 | 结果 | 证据 |
|---|----|------|------|
| P1-1 | **仅内听 bind**；外口（示例端口，含非标）无 userspace listen（`ss`） | ☐ PASS / ☐ FAIL / ☐ BLOCKED | |
| P1-2 | **同外口 HTTP**：`curl -sS http://127.0.0.1:<PORT>/` 进入 WAF/OpenResty（非玩具文案） | ☐ PASS / ☐ FAIL / ☐ BLOCKED | |
| P1-3 | **同外口 HTTPS**：对**同一 `<PORT>`** `curl -sk https://127.0.0.1:<PORT>/`（按需 `--resolve` / `-servername`）TLS 握手成功并进入引擎 | ☐ PASS / ☐ FAIL / ☐ BLOCKED | |
| P1-4 | **同口双协议（生产语义）**：P1-2 与 P1-3 在**同一外口**均 PASS（`https_allow_http`） | ☐ PASS / ☐ FAIL / ☐ BLOCKED | stock 无指令 → **BLOCKED** + 模拟边界说明 |
| P1-5 | **证书观感**：握手成功；证书来自引擎侧；SNI/ALPN 与「直连旧架构」一致或文档说明差异 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-6 | **默认藏头**：对外响应**不**含 `X-Waf-External-Port`（及同类调试头） | ☐ PASS / ☐ FAIL / ☐ BLOCKED | |
| P1-7 | **Probe 可验**：打开 probe flag 后，可从约定通道（头 / 专用 path / 日志）读到正确 `$waf_external_port`；至少两外口可区分；**≠ 内听端口** | ☐ PASS / ☐ FAIL / ☐ BLOCKED | |
| P1-8 | **负向**：`close-port` / map delete 后该外口 HTTP 与 HTTPS **均**不可达；邻口仍可用 | ☐ PASS / ☐ FAIL / ☐ BLOCKED | |
| P1-9 | **版本备注**：引擎版本字符串（1.19.3.2 或同代 + 是否含 `https_allow_http`） | ☐ PASS / ☐ FAIL / ☐ BLOCKED | |

## 建议命令（Repo PR 落地后填端口/证书）

```bash
PORT=<steered_external_port>   # e.g. 18081 — NOT "HTTPS-only 8443 architecture"
HOST=127.0.0.1

# P1-1
ss -lntp | rg -E ":(8080|${PORT})\\b" || true

# P1-2 / P1-6（默认无探针）
curl -sS -D- "http://${HOST}:${PORT}/" | tee /tmp/p1-http.hdr
rg -i 'X-Waf-External-Port' /tmp/p1-http.hdr && echo 'FAIL: header leaked' || echo 'PASS: no external_port header'

# P1-3 / P1-4（同口 HTTPS）
curl -sk -D- --resolve "${HOST}:${PORT}:${HOST}" "https://${HOST}:${PORT}/" | tee /tmp/p1-https.hdr
# SNI example:
# curl -sk --resolve example.test:${PORT}:127.0.0.1 https://example.test:${PORT}/ -v

# P1-7（探针开）
# WAF_EXTERNAL_PORT_PROBE=1 或 PR 约定开关后再 curl，断言外口值

# P1-8
./run-openresty-demo.sh close-port "$PORT"   # 或 PR 等价 CLI
curl -sS --max-time 3 "http://${HOST}:${PORT}/"   ; echo http_exit:$?
curl -sk --max-time 3 "https://${HOST}:${PORT}/"  ; echo https_exit:$?
```

## 结论栏（执行后）

- **总体**: ☐ PASS · ☐ FAIL · ☐ BLOCKED
- **PR**:
- **引擎版本 / `https_allow_http`**:
- **Probe flag 名**:
- **阻塞 / 交还 Repo**:
- **时间 (Asia/Shanghai)**:

---
*作者: Test · Json P1 分工 + Alex 同口 HTTP/HTTPS 增量 · 实测待 Repo P1 PR*
