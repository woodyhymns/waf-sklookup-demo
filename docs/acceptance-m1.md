# M1 验收清单：sk_lookup → OpenResty（接线 POC）

- **里程碑**: [可执行里程碑：sk_lookup → OpenResty WAF](https://app.notion.com/p/3ba6e599de1981b292abfec7ccd84417)
- **分支**: `feat/openresty-integration`
- **状态**: Test 已执行 · 核心 M1-1…M1-5 **全部 PASS**（未 merge / 未 deploy；见 `docs/acceptance-m1-run.log`）
- **PR**: https://github.com/woodyhymns/waf-sklookup-demo/pull/1 （`feat/openresty-integration` → `main`）
- **执行人**: Test（QA）
- **总体结论**: **PASS** — 核心五项全绿；扩展项见下表

## Automation / 自动化

本地优先（对齐本清单 M1-1…M1-5）。驱动 `./run-openresty-demo.sh`（start → verify → close-port → stop；EXIT 始终 stop）：

```bash
OPENRESTY_PREFIX=/usr/local/openresty ./scripts/accept-m1.sh
# 等价: make accept-m1
```

- 覆盖核心必过 **M1-1…M1-5**（含 close-port 负向）；可选未开通口（默认 `18083`）。
- 机器可读摘要: `docs/acceptance-m1-last.json`（脚本生成，勿手改）。
- 本文件历史 PASS 证据保留（见 `docs/acceptance-m1-run.log`）；复验以 JSON + 终端为准。
- CI: 仅适合 self-hosted Linux + BPF `sk_lookup` + OpenResty **1.19.3.2**；默认不配 GitHub-hosted workflow。

## 环境约束（硬性）

| 项 | 要求 | 实测 / 备注 |
|----|------|-------------|
| OpenResty | **1.19.3.2** 基线（或明确同代 / 兼容子集；勿依赖更高版本 API） | `nginx version: openresty/1.19.3.2`；`OPENRESTY_PREFIX=/usr/local/openresty`。本机无 docker/apt 旧包；从 Docker Hub 镜像 `openresty/openresty:1.19.3.2-bionic` amd64 层解压（`openresty -V` → built by gcc 7.5.0 Ubuntu 18.04） |
| 内核 | ≥5.9，`sk_lookup` available（`bpftool feature`） | `6.12.94+`；`bpftool feature list_builtins prog_types` → `sk_lookup` |
| 权限 | root 或 `CAP_BPF` + 必要 net caps | loader via `sudo`；OK |
| 外口变量 | **必须** `$waf_external_port`（或文档约定等价名）；**禁止**用裸 `$server_port` 当业务外口 | 响应头 `X-Waf-External-Port` + body/access_log `waf_external_port=`；内听恒为 8080 |
| 非目标 | 不验收玩具 HTTP；不做 M2 热加删 API / M3 压测矩阵 | 本跑核心 M1-1…5；M1-6 TLS = N/A |

预检命令（执行时粘贴输出）：

```bash
openresty -v 2>&1 || nginx -V 2>&1
uname -r
sudo bpftool feature list_builtins prog_types | rg sk_lookup
```

实测输出（2026-08-13 01:17 CST）：

```text
nginx version: openresty/1.19.3.2
6.12.94+
sk_lookup
```

## 核心验收（Json 要求 · 必过）

| # | 项 | 结果 | 证据（命令 / 日志摘录） |
|---|----|------|------------------------|
| M1-1 | **仅内听 bind；外口靠 sk_lookup** — `ss -lntp`（或等价）仅见 OpenResty **固定内听**；外口（含非标如 65500）**无** userspace `listen`/`bind` | ☑ PASS / ☐ FAIL / ☐ BLOCKED | `ss -lntp` 仅 `127.0.0.1:8080` openresty；18081/18082/65500 无 userspace LISTEN（verify PASS） |
| M1-2 | **curl/外口命中真实 OpenResty** — 打已开通外口得到引擎响应（TLS/HTTP 路径来自 OpenResty），**不是** demo 玩具 HTTP（无 `sk_lookup demo OK` 玩具文案） | ☑ PASS / ☐ FAIL / ☐ BLOCKED | 外口 curl 得 `Server: openresty/1.19.3.2` + body `OpenResty M1 OK`；无玩具文案 `sk_lookup demo OK` |
| M1-3 | **响应或日志可见正确外口** — `$waf_external_port`（或等价）= Client 打的目的端口；至少两外口可区分（例 18081 ≠ 18082 / 65500）；**不得**误报为内听端口 | ☑ PASS / ☐ FAIL / ☐ BLOCKED | 18081/18082/65500 各自 `X-Waf-External-Port`/`waf_external_port=` 等于目的端口且 ≠8080；access_log 可区分 |
| M1-4 | **负向：删 map 端口后外口失败** — `bpftool map delete`（或约定 CLI）去掉某外口后，新连接该口失败；其它仍开通口可用（约定范围内） | ☑ PASS / ☐ FAIL / ☐ BLOCKED | `./run-openresty-demo.sh close-port 18081` 后 18081 connect fail；18082 仍 200；dump-ports 仅 18082,65500 |
| M1-5 | **版本备注** — 本次跑在 OpenResty **1.19.3.2**（或同代，写明实际版本字符串） | ☑ PASS / ☐ FAIL / ☐ BLOCKED | `openresty -v` → `nginx version: openresty/1.19.3.2`；`Server: openresty/1.19.3.2`；精确基线（镜像层解压，非同代近似） |

## Notion M1 扩展勾选（对齐里程碑页）

| # | 项 | 结果 | 证据 |
|---|----|------|------|
| M1-6 | 已开通外口（含非标）→ **TLS 握手成功**；证书 / SNI / ALPN 与「直连旧架构」观感一致（M1 至少：握手成功 + 证书来自 OpenResty） | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☑ N/A | 本 PR 为 HTTP；清单对照表标 N/A（无 TLS 路径） |
| M1-7 | access / Lua 日志含 **真实客户端 IP** + **`$waf_external_port`** | ☑ PASS / ☐ FAIL / ☐ BLOCKED | access_log：`127.0.0.1:… waf_external_port=18081/18082/65500`；body `remote_addr=127.0.0.1` |
| M1-8 | Lua WAF 规则仍生效；回源口可与监听口不同（若 PR 含 WAF 路径） | ☐ PASS / ☐ FAIL / ☐ BLOCKED / ☑ N/A | 本 PR 仅 external_port Lua 接线 POC，无独立 WAF 规则/回源矩阵 |
| M1-9 | **未开通**端口：失败 / RST，无残留对外暴露 | ☑ PASS / ☐ FAIL / ☐ BLOCKED | 未开通 `18083`：`curl` exit 7 Could not connect；ss 无该口 LISTEN |
| M1-10 | 复现步骤可按 `docs/repro.md` 风格跑通（更新或附 M1 repro 段） | ☑ PASS / ☐ FAIL / ☐ BLOCKED | `OPENRESTY_PREFIX=/usr/local/openresty ./run-openresty-demo.sh start|verify|close-port|stop` 按文档跑通；详见 run.log |

## 建议执行步骤（Repo PR 就绪后）

1. 检出 PR 分支；确认 OpenResty **1.19.3.2**（或同代）与 loader / 配置路径。
2. 按 PR / README 启动：attach `sk_lookup` → 注册 OpenResty listen FD → 写入 `open_ports`。
3. **M1-1**: `ss -lntp | rg -E '18080|18081|18082|65500|<内听>|<外口>'` — 只应有内听。
4. **M1-2 / M1-6**: 对外口 `curl -vk https://127.0.0.1:<外口>/`（或 PR 约定 scheme）；确认响应体 / Server 头 / 证书归属 OpenResty，排除玩具文案。
5. **M1-3 / M1-7**: 打两个不同外口；从响应头、自定义 body、或 access/Lua 日志读取 `$waf_external_port`；断言等于目的端口且 ≠ 内听。
6. **M1-4**: `sudo bpftool map dump name open_ports` → delete 一键 → 该口 connect fail；邻口仍 200/握手成功。
7. **M1-9**: 从未写入 map 的端口应不可达。
8. 填写本表 + 环境表；结论 **PASS** 仅当核心五项（M1-1…5）全绿。
9. 清理进程 / BPF attach；不 deploy、不 merge、不 page。

### 负向示例（端口删除）

```bash
# 以 PR 实际 map 名 / 键格式为准（demo 曾用 open_ports，LE u16）
sudo bpftool map dump name open_ports
sudo bpftool map delete name open_ports key hex <port_le_bytes>
curl -sS --max-time 3 https://127.0.0.1:<deleted_port>/   # expect fail
```

### `$waf_external_port` 断言示例

```bash
# 示例：引擎把变量打进响应头或 JSON（以 PR 为准）
curl -sS -D- http://127.0.0.1:18081/ | rg -i 'waf.external|18081'
# 日志侧：access_log / Lua 打印应含 external=18081，且不得写成内听端口
```

## 本 PR 实现对照（Repo 约定 · 不代替勾选）

下列把清单里的占位符落到本 PR 的具体路径。Test 仍按上面 **M1-1…M1-5** 填 PASS/FAIL。

| 清单项 | 本 PR |
|--------|--------|
| 固定内听 | `127.0.0.1:8080`（**不是**玩具口 `:18080`） |
| 已开通外口 | `18081`, `18082`, `65500` |
| Scheme | **HTTP** `http://127.0.0.1:<port>/`（清单步骤里的 `https://` 对应扩展项 **M1-6**，本 PR 标 N/A） |
| `$waf_external_port` | nginx `set` + Lua；响应头 `X-Waf-External-Port`；access_log `waf_external_port=`。**禁止**用 `$server_port`（常为 `8080`） |
| Map | BPF 名 `open_ports`（u16 LE）；pin `/sys/fs/bpf/waf-sklookup/open_ports` |
| OpenResty | **1.19.3.2**（`openresty/openresty:1.19.3.2-bionic` 或同代；`openresty -v` / `Server` 头） |
| 启动 | `./run-openresty-demo.sh start` 然后 `verify` |

```bash
# M1-1
ss -lntp | rg -E ':(8080|18081|18082|65500)\b'   # 只应有 127.0.0.1:8080

# M1-2 / M1-3（HTTP；不要用玩具文案 sk_lookup demo OK）
curl -sS -D- http://127.0.0.1:18081/ | rg -i 'openresty|waf.external|18081'
curl -sS -D- http://127.0.0.1:18082/ | rg -i 'waf.external|18082'

# M1-4 — CLI 或 bpftool（18081 = 0x46A9 → LE key hex a9 46）
sudo bpftool map dump name open_ports
sudo bpftool map dump pinned /sys/fs/bpf/waf-sklookup/open_ports
sudo bpftool map delete name open_ports key hex a9 46
# 等价：./run-openresty-demo.sh close-port 18081
curl -sS --max-time 3 http://127.0.0.1:18081/   # expect fail
curl -sS http://127.0.0.1:18082/                # still 200

# M1-5
openresty -v 2>&1   # nginx version: openresty/1.19.3.2
```

## 失败与最小修复建议（跑完再填）

| 现象 | 最小建议 |
|------|----------|
| 仍命中玩具 HTTP / `sk_lookup demo OK` | loader 未把 FD 换成 OpenResty listen；检查 sockmap/redir 注册 |
| `$server_port`==内听且无 `$waf_external_port` | **FAIL** — 必须另通道灌外口（BPF 元数据 / original dst / 约定模块）；勿放行 |
| OpenResty >1.19 且用了新 API | 降到 1.19.3.2 或删掉高版本依赖后重验 |
| attach / map 权限失败 | root、`bpftool feature`、节点是否禁 BPF |
| multi-worker 连错 / 失败 | M1 先单 worker 或按 1.19.3.2 reuseport 行为收窄 |
| 本机无 openresty/docker（本跑已解） | 解压官方 `1.19.3.2-bionic` 镜像层到 `/usr/local/openresty`，或装 docker+host 网络镜像；勿用 apt 最新版冒充基线 |

## 结论栏（执行后填写）

- **总体**: ☑ PASS · ☐ FAIL · ☐ BLOCKED
- **PR**: https://github.com/woodyhymns/waf-sklookup-demo/pull/1
- **OpenResty 版本字符串**: `nginx version: openresty/1.19.3.2`（`/usr/local/openresty`，源自 Docker Hub `openresty/openresty:1.19.3.2-bionic` amd64 层；`openresty -V` built by gcc 7.5.0 / OpenSSL 1.1.1k）
- **内核**: `6.12.94+`（`sk_lookup` available）
- **阻塞 / 交还 Repo 的项**: 无。核心五项全绿。`CGO_ENABLED=0 make build && make test` 直接通过（无需改名 `dispatch.bpf.c`）。未 merge / 未 deploy。
- **报告时间 (Asia/Shanghai)**: 2026-08-13 01:17 CST
- **运行日志**: `docs/acceptance-m1-run.log`
- **安装尝试纪要**: ① PATH 无 openresty/nginx/docker/podman/nerdctl；② apt OpenResty 仓无 1.19.3.2（仅 ≥1.25）；③ libpcre3-dev 在 Debian 13 不可用、源码构建受阻；④ 下载官方镜像层并解压至 `/usr/local/openresty`（成功，精确 1.19.3.2）

---
*清单作者: Test · 对齐 Json M1 开工指令 + Notion 里程碑验收标准*
*Repo 仅追加「本 PR 实现对照」与 PR 链接，不代填 PASS/FAIL*
