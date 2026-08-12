# P1 验收：同一内听 HTTP+HTTPS + 隐藏外口头

- **分支**: `feat/product-p1-tls-and-headers`
- **PR**: （填）
- **基线引擎**: OpenResty **1.19.3.2**（demo 镜像 `openresty/openresty:1.19.3.2-bionic`）
- **产品引擎**: 带 Tengine **`https_allow_http`** 的 OpenResty（每条 listen **同时**收明文 HTTP 和 TLS）
- **不要 merge**

产品约束：sk_lookup 只把外口导向固定内听；**协议由 OpenResty 选**，不是 8080=HTTP / 8443=TLS 的产品模型。

## 双协议用例（先看这个）

| # | 用例 | 谁必须过 | 命令 | 结果 |
|---|------|----------|------|------|
| **P1-A** | **同一外口** `http://` **和** `https://` 都成功 | **Tengine `https_allow_http`** | `curl -sS http://127.0.0.1:18081/` **且** `curl -sk https://127.0.0.1:18081/` | ☐ PASS / ☐ FAIL / ☑ N/A on stock 1.19.3.2 |
| **P1-B** | 库存镜像 TLS 握手（**另一条**内听，**不是**产品模型） | stock 1.19.3.2 fallback | `curl -sk https://127.0.0.1:18443/` → `127.0.0.1:8443 ssl` | ☐ PASS / ☐ FAIL / ☐ N/A |

`./run-openresty-demo.sh verify` 会跑 P1-A 探测：Tengine 上应 PASS；库存 1.19.3.2 上打印 **N/A**（HTTPS 打到 HTTP 内听失败），**不**把 verify 判失败。

## 其余 P1

| # | 项 | 引擎 | 结果 |
|---|----|------|------|
| P1-1 | 外口无 userspace LISTEN；仅固定内听 | 两者 | ☐ |
| P1-2 | 默认响应 **无** `X-Waf-External-Port` | 两者 | ☐ |
| P1-3 | access_log 仍有 `waf_external_port=` | 两者 | ☐ |
| P1-4 | `WAF_EXPOSE_EXTERNAL_PORT=1` 后响应头出现 | 两者 | ☐ |
| P1-5 | `openresty -v` 为 1.19.3.2（本 demo）或写明 Tengine 版本 | 按环境 | ☐ |

生产 listen（库存镜像 `nginx -t` 会报 `invalid parameter "https_allow_http"`）：

```nginx
listen 127.0.0.1:8080 ssl https_allow_http;
```

详见 [docs/openresty-p1.md](openresty-p1.md)。
