# WAF 动态非标端口：同机薄入口 + OpenResty 终结 TLS

## 目标

- Client → WAF 节点（无独立前置代理集群）
- 支持运行时增加/删除任意非标端口，不发 OpenResty 新版本
- **TLS 仍在 OpenResty 终结**，端到端观感与现网一致（证书、SNI、ALPN、Lua SSL 变量）
- 转发性能优先：入口只做 TCP，不二次 TLS、不二次完整 HTTP 反代
- 数据面尽量克制：现有 OpenResty + Lua WAF 保留；仅同机增加薄 accept

## 总览

```
Client
  |  TCP (TLS bytes opaque)
  v
[thin-accept on WAF node]  -- 动态 bind 已开通端口
  |  TCP + 原始目的端口信息
  v
[OpenResty 127.0.0.1 / UDS] -- ssl_certificate + Lua WAF + 回源
  v
Origin
```

控制面：域名/端口开通表 → 推送到节点 → thin-accept 热 listen；OpenResty 配置不因「多一个业务端口」而改 listen 列表。

---

## PROXY protocol vs TPROXY

### 方案 A：PROXY protocol v2（推荐作为默认 POC/首发）

**做法**

1. thin-accept 对外 `bind(已开通端口)`，接受 Client TCP。
2. 与 OpenResty 建立本机连接（优先 **Unix domain socket**）。
3. 先发 **PROXY protocol v2** 头，带上：
   - `src` = 真实客户端 IP:port
   - `dst` = 对外 VIP:业务端口（关键：保留原始目的端口）
4. 随后透传 TLS/TCP 字节，不做解密。
5. OpenResty `listen ... proxy_protocol`；用 `realip` / `$proxy_protocol_addr`、`$proxy_protocol_port`，以及解析到的目的端口映射为「对外 server_port」。

**优点**

- 实现直观，不依赖复杂内核透明代理
- 容器/普通网卡环境都好落地
- 真实客户端 IP + 对外端口都可保留
- 与「TLS 在 OpenResty」天然兼容（纯 TCP 透传）

**缺点**

- OpenResty 与 accept 之间多一段 PROXY 头处理（本机，成本通常很小）
- 必须保证内部口**只接受来自 accept 的连接**（否则有伪造 PROXY 头风险）
- nginx 对 PROXY v2 目的端口的暴露方式要在 POC 里验证（见下文「OpenResty 变量」）

**安全**

- 内部 listen 仅 `127.0.0.1` 或 UDS 文件权限 `0600` + 同用户
- 绝不对公网开启 `proxy_protocol` listen

### 方案 B：TPROXY + IP_TRANSPARENT

**做法**

1. iptables/nftables（或类似）把「已开通端口」的入站流量 TPROXY 到本机 accept/OpenResty。
2. 进程 `IP_TRANSPARENT` / `IP_ORIGDSTADDR`，拿到原始 dst。
3. 可让 OpenResty 直接以透明方式看到原目的地址，或仍经极薄 accept 再交引擎。

**优点**

- 对引擎更「像真的听在业务端口上」
- 某些路径可减少用户态封装

**缺点**

- 依赖 netfilter/能力（`CAP_NET_ADMIN` 等），容器与多租户节点更麻烦
- 运维与排障成本明显高于 PROXY
- 和现有部署模型耦合深，POC 慢

### 推荐

| 阶段 | 选择 |
|------|------|
| POC / 首发 | **PROXY protocol v2 + 本机 UDS** |
| 性能极致且内核可控 | 再评估 TPROXY |

先把产品语义（任意非标口、TLS 观感一致）跑通，再用基线压测决定要不要上 TPROXY。

---

## 组件职责

### thin-accept（新，同机）

- 拉取/watch 端口开通表：`(vip|*, port, proto tcp)`
- 热 `bind` / `unbind`；未开通端口不听，或听了立刻 RST（按产品选择）
- TCP accept 后：连 OpenResty 内部口，写 PROXY v2，再双向 splice/copy
- **不做** TLS、不做 WAF 规则、不做 HTTP 解析
- 暴露 metrics：listen 集合、accept QPS、到引擎失败数、P99 本机转发延迟

### OpenResty（现有）

- 固定内部 listen（示例）：
  - UDS：`unix:/run/waf/engine.sock proxy_protocol`
  - 或 `127.0.0.1:2443 proxy_protocol`（仅本机）
- TLS 终结、证书、SNI、Lua WAF、回源逻辑基本不变
- 从 PROXY 恢复：
  - 客户端 IP → `set_real_ip_from` + `real_ip_header proxy_protocol`
  - 对外端口 → 见下一节

### 控制面

- API：为域名增加/删除监听端口（与回源端口分离）
- 配额、端口黑名单（22/3306/…）
- 下发到节点；等待 accept ACK 后再标「已生效」

---

## OpenResty：原始目的端口怎么用

业务侧常见依赖：`$server_port`、按端口差异化策略、访问日志。

内部统一 listen 后，`$server_port` 会变成内部口（或 0/unix），**不能直接当对外端口**。

推荐约定：

1. thin-accept 在 PROXY v2 中填写 `dst.port = 对外业务端口`。
2. OpenResty 用可用变量拿到目的端口，写入 `$waf_external_port`（lua/模块）。
3. 日志与规则统一改用 `$waf_external_port`，而不是裸 `$server_port`。

POC 验收必须单测：请求打到 `:8080` 与 `:8443` 时，引擎侧看到的对外端口不同。

> 若当前 OpenResty/nginx 版本对 PROXY v2 dst port 暴露不完整，可在 v2 头后增加 **1 行私有 preamble**（仍在 TLS 之前）由 stream/lua 读取——仅作兜底，优先标准 PROXY。

---

## 示例配置（示意）

### OpenResty http（HTTPS，TLS 在此终结）

```nginx
stream {
  # 若用 stream 接 PROXY 再 ssl_preread，也可；此处示意 http 侧直接 proxy_protocol
}

http {
  set_real_ip_from 127.0.0.1;
  real_ip_header proxy_protocol;

  server {
    listen unix:/run/waf/engine.sock ssl proxy_protocol;
    # http2 等保持与现网一致的能力开关

    ssl_certificate     /etc/waf/certs/site.pem;
    ssl_certificate_key /etc/waf/certs/site.key;
    # 多证/SNI：保持现有 lua 或 map 逻辑

    # 伪代码：从 proxy protocol 取对外端口
    # set $waf_external_port $proxy_protocol_port_dst;  # 以实际模块为准

    location / {
      access_by_lua_block { -- 现有 WAF
      }
      proxy_pass http://origin;
    }
  }
}
```

内部口不对公网暴露；公网只打到 thin-accept 动态端口。

### thin-accept 行为伪代码

```
on_config_update(ports):
  for p in ports-added: start_listener(p)
  for p in ports-removed: drain_and_stop(p)

on_accept(client_conn, local_port):
  eng = dial_uds("/run/waf/engine.sock")
  eng.write(proxy_v2_header(
      src=client_conn.peer, dst=(vip, local_port)))
  bidirectional_copy(client_conn, eng)  # prefer splice
```

---

## 性能清单

- [ ] 本机 UDS，避免 127.0.0.1 TCP
- [ ] 入口无 TLS、无 HTTP 反代
- [ ] 双向转发优先 `splice` / 高效 copy；worker 与 CPU 亲和
- [ ] `SO_REUSEPORT` 多 accept worker
- [ ] 压测对比基线：直连 OpenResty vs accept+OpenResty（QPS、P99、CPU）
- [ ] 目标：同机多一跳损耗控制在可接受范围（常见可到个位数百分比；以你们机型实测为准）

---

## POC 验收

1. 动态加 `8080`/`8443`，不 reload OpenResty，外部可访问
2. 动态删端口后，连接失败或 RST；引擎无残留对外暴露
3. `openssl s_client` / 浏览器看证书与直连旧架构一致
4. 访问日志中客户端 IP 为真实 IP，对外端口正确
5. Lua WAF 规则仍生效；回源端口可与监听端口不同
6. 未授权来源无法直连 engine.sock 伪造 PROXY
7. 加删端口过程中 P99 无明显尖刺；长连接策略符合预期（drain）

---

## 里程碑建议

1. **M1**：固定两个端口的手工 thin-accept + PROXY + OpenResty 内部口（证明 TLS 观感）
2. **M2**：控制面推送端口集合，热加删
3. **M3**：压测与观测；决定是否优化 TPROXY
4. **M4**：配额/黑名单/多域名证书与现网控制台打通

## 非目标（本阶段不做）

- 入口终结 TLS
- 用 Envoy 全家桶（可选实现，非必须）
- 改写 Lua WAF 规则引擎

---

## 附录：BPF（sk_lookup）方案分析

### 它解决什么

Linux **BPF_PROG_TYPE_SK_LOOKUP**（约 5.6+，生产上常见要求更新内核）在传输层做 socket 查找时介入：用 `bpf_sk_assign()` 把打到「任意 IP:port」的新连接，派给**已经 listen 的那一个 socket**。

内核文档明确点名用例：L7 proxy 不想为每个端口各 `bind()` 一个 socket。Cloudflare Spectrum / Tubular 等边缘代理用的就是这类思路。

对你意味着：

```
Client :8080 / :8443 / :任意已开通端口
        |
        v  (sk_lookup: port in allow-map? -> assign OpenResty listen sock)
OpenResty 单个（或 reuseport 一组）listen socket
        |
        TLS 终结 + Lua WAF + 回源   ← 与现网一致
```

控制面「开通端口」= **更新 BPF map**，不必用户态再 bind 一遍，也不必 reload OpenResty。

### 和 thin-accept / TPROXY 比

| 维度 | PROXY + thin-accept | TPROXY | **BPF sk_lookup** |
|------|---------------------|--------|-------------------|
| 数据面用户态多一跳 | 有 | 可选 | **无（直达 OpenResty）** |
| TLS 在 OpenResty | 易 | 易 | **天然** |
| 动态加端口 | accept bind | 规则/端口集 | **改 BPF map** |
| 内核/权限 | 低 | 中高 | 中高（BPF、netns） |
| 运维复杂度 | 中 | 高 | 中高（程序、map、升级、观测） |
| 原始目的端口 | PROXY 头带上 | 内核原目的 | **要单独设计**（见下） |
| 性能潜力 | 好（本机） | 很好 | **通常最好（无用户态转发）** |

### 原始目的端口（重要）

连接被 assign 到「内部 listen socket」后，应用里 `getsockname` / nginx `$server_port` **常常变成该 listen 的绑定端口**，而不是 Client 打的 8080。

所以 BPF 方案同样要约定如何让 WAF 知道对外端口，例如：

1. 接受连接后用合适的 API/机制取 **original dst**（视内核与部署而定，需 POC 验证）；或  
2. 用 BPF 与用户态共享的元数据通道；或  
3. 规则/日志统一走显式的 `$waf_external_port`，在入口最早处写入。

**POC 必须单测：8080 vs 8443 在 Lua/日志里能区分。** 这点和 PROXY 方案一样关键，只是携带方式不同。

### 未开通端口

sk_lookup 里：port **不在** allow-map → `SK_PASS`（走内核默认，通常无 listener 则失败）或按策略 `SK_DROP`。可对齐「未配置不转发」；若要「握手后 RST」的精确语义，要再对一下 TCP 状态机表现是否与产品文案一致。

### 落地组件（比 thin-accept 更「内核态」）

1. OpenResty：固定 listen（reuseport 可选），socket 放入 `SOCKMAP`/`SOCKHASH`  
2. 小控制进程：加载 sk_lookup、挂到 netns、把 engine socket 塞进 map、watch 端口开通表写 `ports` map  
3. **不必**再挂用户态 TCP 转发进程（这是相对方案 3 的最大结构差异）

### 风险与前提

- 内核版本与发行版支持（容器/旧内核直接否决）  
- 权限与安全：BPF 加载、netns、与其他 CNI/安全软件的 sk_lookup 冲突  
- OpenResty/nginx 与 reuseport：assign 到 reuseport group 时的行为要验证  
- 团队要会运维 BPF（ci、回滚、`bpftool`、故障时一键卸钩子恢复）  
- 比 PROXY POC **更重**，但若「任意端口 + 极致转发性能 + TLS 仍在 OpenResty」三者同时要，它是最漂亮的长期解

### 建议怎么放进路线图

| 阶段 | 策略 |
|------|------|
| M1–M2 | 仍用 **PROXY + thin-accept** 验证产品语义与 TLS 观感（快） |
| 并行调研 | 目标内核上跑 sk_lookup demo：多端口 → 单 OpenResty socket + 目的端口可见性 |
| M3+ | 若本机 PROXY 跳成为 CPU/延迟瓶颈，或端口规模很大，**再切 BPF sk_lookup**，去掉用户态 accept 转发 |

一句话：BPF 不是旁支，而是「方案 3 的内核态升级版」——往往**不再需要**用户态薄入口做 copy，但仍要解决对外端口可见性与平台内核前提。
