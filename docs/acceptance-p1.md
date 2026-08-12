# P1 验收：同一内听 HTTP+HTTPS + 隐藏外口头

- **分支**: `feat/product-p1-tls-and-headers`
- **PR**: https://github.com/woodyhymns/waf-sklookup-demo/pull/4
- **Tip SHA**: `cef65ab` / harness `ba5c216` (HAH runtime on box)
- **基线引擎**: OpenResty **1.19.3.2**（本机 `/usr/local/openresty`；源自 1.19.3.2-bionic）
- **产品引擎**: 带 Tengine **`https_allow_http`** 的 OpenResty（每条 listen **同时**收明文 HTTP 和 TLS）— **本跑使用自编 OpenResty-HAH** `/usr/local/openresty-hah`（移植 `https_allow_http`）
- **执行人**: Test（QA）· 2026-08-13 07:45–07:46 Asia/Shanghai
- **总体**: stock fallback 此前 **PASS**；**P1-A 同口双协议（HAH）: PASS**（2026-08-13）— merge 等 Alex
- **不要 merge**

> **Merge gate (Alex):** **P1-A 已在 HAH PASS**（见下）。合入仍由 Alex 决定；Test **不 merge**。

产品约束：sk_lookup 只把外口导向固定内听；**协议由 OpenResty 选**，不是 8080=HTTP / 8443=TLS 的产品模型。文档（PR 描述 / `docs/openresty-p1.md` / `nginx.conf` 注释 / tengine example）已写清 `https_allow_http` → **文档清晰：YES**。

## 双协议用例（先看这个）

| # | 用例 | 谁必须过 | 命令 | 结果 |
|---|------|----------|------|------|
| **P1-A** | **同一外口** `http://` **和** `https://` 都成功 | **HAH / `https_allow_http`** | `curl -sS http://127.0.0.1:18081/` **且** `curl -sk https://127.0.0.1:18081/` | ☑ **PASS**（HAH `/usr/local/openresty-hah`；body `scheme=http` / `scheme=https`，`waf_external_port=18081`；默认无 X-Waf-External-Port） / ☐ FAIL / ☐ N/A |
| **P1-B** | 库存镜像 TLS 握手（**另一条**内听，**不是**产品模型） | stock 1.19.3.2 fallback | `curl -sk https://127.0.0.1:18443/` → `127.0.0.1:8443 ssl` | ☑ **PASS** / ☐ FAIL / ☐ N/A |

`./run-openresty-demo.sh verify` 会跑 P1-A 探测：Tengine 上应 PASS；库存 1.19.3.2 上打印 **N/A**（HTTPS 打到 HTTP 内听失败），**不**把 verify 判失败。

## 其余 P1

| # | 项 | 引擎 | 结果 |
|---|----|------|------|
| P1-1 | 外口无 userspace LISTEN；仅固定内听 | 两者 | ☑ **PASS**（ss：仅 `127.0.0.1:8080` + stock fallback `127.0.0.1:8443`；无 18081/18082/65500/18443 userspace LISTEN） |
| P1-2 | 默认响应 **无** `X-Waf-External-Port` | 两者 | ☑ **PASS**（expose=off；`:18081` 响应头 NO_LEAK） |
| P1-3 | access_log 仍有 `waf_external_port=` | 两者 | ☑ **PASS**（`waf_external_port=18081/18082/65500/18443`） |
| P1-4 | `WAF_EXPOSE_EXTERNAL_PORT=1` 后响应头出现 | 两者 | ☑ **PASS**（`X-Waf-External-Port: 18081`） |
| P1-5 | `openresty -v` 为 1.19.3.2（本 demo）或写明 Tengine 版本 | 按环境 | ☑ **PASS**（`nginx version: openresty/1.19.3.2`） |

附加（stock）：HTTP 导向口 body `OpenResty M1 OK`；`close-port 18081` 后该口 fail、邻口 18082 仍 200 → PASS。

生产 listen（库存镜像 `nginx -t` 会报 `invalid parameter "https_allow_http"`）：

```nginx
listen 127.0.0.1:8080 ssl https_allow_http;
```

详见 [docs/openresty-p1.md](openresty-p1.md)。证据：`docs/acceptance-p1-run.log`。

注：`docs/acceptance-p1-tls.md` **absent** on this branch (harness PR #3); dual-protocol items mapped here.


## P1-A HAH run (2026-08-13 Asia/Shanghai)

- `OPENRESTY_PREFIX=/usr/local/openresty-hah ./scripts/accept-p1-a-dual.sh` → **EXIT 0 / PASS**
- Log: `docs/acceptance-p1-a-hah-run.log`
- **勿 merge** — 等 Alex 决定合入 PR #4
