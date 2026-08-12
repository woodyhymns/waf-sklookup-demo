# P1 TLS 验收清单（草稿）/ P1 TLS Acceptance Checklist (Draft)

- **里程碑**: Notion productization **P1**（HTTPS on steered ports + header policy）
- **状态**: **DRAFT — awaiting Repo P1 PR** · 勿在本草稿上跑完整 TLS 验收
- **基线**: OpenResty **1.19.3.2**（`nginx version: openresty/1.19.3.2`）
- **依赖**: M1 HTTP 接线已 PASS（`docs/acceptance-m1.md`）；P1 在此之上加 TLS / 外泄策略
- **执行人**: Test（QA）— Repo PR 就绪后再勾选

> Do **not** treat this file as executed evidence. Fill PASS/FAIL only after Repo lands P1 TLS listen + probe flag.

## 环境约束（硬性）

| 项 | 要求 | 实测 / 备注 |
|----|------|-------------|
| OpenResty | **1.19.3.2** 基线；TLS 终止在 OpenResty（非外部 LB 代终结冒充） | ☐ `openresty -v` → `1.19.3.2` |
| 内核 | ≥5.9，`sk_lookup` | ☐ |
| 外口变量 | **Host = name**；**`$waf_external_port` = ingress / 客户目的端口**；**禁止**用 `$server_port` 当业务外口 | ☐ |
| 内听 | OpenResty **仅**固定内听（例 `127.0.0.1:8080` 或 PR 约定）；外口经 sk_lookup | ☐ `ss -lntp` |
| TLS 外口示例 | 至少 **8443** 和/或非标 TLS 口（PR 写明） | ☐ |
| 生产默认 | **不外泄** `X-Waf-External-Port`（或同类）到外部响应 | ☐ |
| 探针 | **probe flag ON** 时仍可验证 `$waf_external_port`（头 / body / log） | ☐ flag 名见下 |

### Probe flag（名待 Repo 确认）

Repo 尚未最终命名时，清单使用占位 **`probe flag`**。建议候选（任选其一落地并回写本表）：

| 候选 | 形态 | 备注 |
|------|------|------|
| `WAF_EXTERNAL_PORT_PROBE` | 环境变量 / `env` | 推荐默认名 |
| `waf_external_port_probe` | nginx/`set`/`map` 变量 | 配置侧开关 |
| `--probe-external-port` | loader / 进程 CLI | 若由 loader 注入 |

**约定**:

- **生产默认 OFF**: 外部 HTTPS 响应 **不得**出现 `X-Waf-External-Port`（及同类调试头）。
- **probe ON**: 允许头或 body 或 access/Lua 日志暴露 `$waf_external_port`，供 Test 断言 = 客户目的端口 ≠ `$server_port`。

## 核心验收（P1 must-pass）

| # | 项 | 结果 | 证据（命令 / 日志摘录） |
|---|----|------|------------------------|
| P1-TLS-1 | **外口 HTTPS** — 已开通 TLS 外口（例 **8443** / 非标）握手成功；证书来自 OpenResty 1.19.3.2 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-2 | **SNI / ALPN「观感」** — 至少：握手成功 + 证书链/Subject 归属 OpenResty；与直连旧架构观感一致（能记则记 ALPN h2/http/1.1） | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-3 | **生产默认不外泄** — probe OFF（默认）时，外部响应 **无** `X-Waf-External-Port`（或 PR 约定同类头） | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-4 | **probe ON 可验证** — 打开 `probe flag` 后，头或 body 或日志可见 `$waf_external_port` = 目的端口，且 ≠ 内听/`$server_port` | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-5 | **仅内听 + sk_lookup** — `ss -lntp` 仅见固定内听；TLS 外口无 userspace `LISTEN` | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-6 | **负向：map 删除关闭外口 TLS** — `close-port` / `bpftool map delete` 后该口新连接失败；邻口仍可 HTTPS | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-7 | **语义** — Host=名；`$waf_external_port`=ingress；业务逻辑不读 `$server_port` 当外口 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |
| P1-TLS-8 | **版本备注** — OpenResty **1.19.3.2** 字符串写入结论栏 | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☐ N/A | |

## 建议 curl / openssl 命令（Repo PR 路径就绪后）

```bash
# 版本
openresty -v 2>&1   # expect: nginx version: openresty/1.19.3.2

# P1-TLS-5 bind
ss -lntp | rg -E ':(8080|8443|<tls_port>)\b'   # 只应有内听

# P1-TLS-1 / P1-TLS-2 — 握手 + 证书（-vk：信任自签/演示证书）
curl -vk --max-time 5 https://127.0.0.1:8443/ -o /tmp/p1-body.txt -D /tmp/p1-hdr.txt
# 或:
openssl s_client -connect 127.0.0.1:8443 -servername <SNI_HOST> -alpn h2,http/1.1 </dev/null 2>&1 | rg -i 'subject|issuer|alpn|openresty|protocol'

# P1-TLS-3 — 默认（probe OFF）：不应出现调试头
rg -i 'X-Waf-External-Port' /tmp/p1-hdr.txt && echo 'FAIL leak' || echo 'PASS no leak'

# P1-TLS-4 — probe ON（flag 名以 Repo 为准；下例为建议名）
WAF_EXTERNAL_PORT_PROBE=1 ./run-openresty-demo.sh start   # 或 PR 文档约定方式
curl -vk https://127.0.0.1:8443/ -D- | rg -i 'X-Waf-External-Port|waf_external_port|8443'
# 日志侧亦可: access_log / Lua 含 waf_external_port=8443

# P1-TLS-6 — 负向
./run-openresty-demo.sh close-port 8443   # 或 bpftool map delete
curl -vk --max-time 3 https://127.0.0.1:8443/   # expect fail
curl -vk https://127.0.0.1:<neighbor_tls_port>/ # still OK
```

## 证据槽（执行时粘贴）

| 槽 | 内容 |
|----|------|
| OpenResty `-v` | |
| `ss -lntp` 摘录 | |
| `curl -vk` 握手 / `Server` / 证书 Subject | |
| 默认响应头（证明无外泄） | |
| probe ON 证据（头/body/log） | |
| close-port 后失败 + 邻口成功 | |
| 实际 `probe flag` 名（Repo） | |

## Pass/Fail 总表（勾选汇总）

| 项 | PASS | FAIL | BLOCKED | N/A |
|----|------|------|---------|-----|
| P1-TLS-1 HTTPS 外口 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-2 SNI/ALPN/证书观感 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-3 默认不外泄 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-4 probe 可验证 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-5 仅内听 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-6 map 删除负向 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-7 Host / `$waf_external_port` 语义 | ☐ | ☐ | ☐ | ☐ |
| P1-TLS-8 OpenResty 1.19.3.2 | ☐ | ☐ | ☐ | ☐ |

## 结论栏（Repo P1 PR 后填写 — 现在留空）

- **总体**: ☐ PASS · ☐ FAIL · ☐ BLOCKED · ☑ DRAFT (not run)
- **PR**: _TBD_
- **OpenResty 版本字符串**: _TBD — must be 1.19.3.2_
- **TLS 外口**: _TBD (e.g. 8443, …)_
- **probe flag 实名**: _TBD (suggest `WAF_EXTERNAL_PORT_PROBE`)_
- **报告时间 (Asia/Shanghai)**: _TBD_
- **阻塞 / 交还 Repo**: 等待 P1 TLS PR（listen/cert/SNI、默认隐藏外口头、probe 开关）

---
*清单作者: Test · P1 productization draft · 不对齐前不执行完整 TLS*
*HTTP M1 自动化见 `scripts/accept-m1.sh`；TLS accept 脚本待 P1 PR 后再加*
