# M2 验收：端口控制面（热加删 + bulk 灌图）

- **分支**: `feat/m2-port-control-plane`
- **文档**: [docs/openresty-m2.md](openresty-m2.md)
- **约束**: 不 reload OpenResty；不重 attach BPF；Go loader 为参考实现（Rust 在 M3/perf 之后）
- **M3**: 本里程碑的 `bulk fill` / `scripts/m3-fill-ports.sh` 就是 30K/60K 灌图入口
- **map 上限**: `open_ports.max_entries = 131072`（原 1024 无法装 30K/60K）。内核 memlock 大约 **8–16 MB**（hash 开销，不是 userspace 按端口线性涨）。`bpftool map show name open_ports` 核对。换此二进制后 **重启 loader 一次**（不必 reload OpenResty）。

前置：`./run-openresty-demo.sh start`（`OPENRESTY_PREFIX=/usr/local/openresty` 或 HAH `/usr/local/openresty-hah`）。

| # | 项 | 命令 | 结果 |
|---|----|------|------|
| M2-1 | add 后新端口打到 OpenResty，无 userspace LISTEN | `./run-openresty-demo.sh add 18083` 然后 `curl http://127.0.0.1:18083/` | ☐ |
| M2-2 | remove 后该口失败，邻口仍通 | `./run-openresty-demo.sh remove 18083` | ☐ |
| M2-3 | list / list -count | `sudo ./waf-sklookup-demo list` | ☐ |
| M2-4 | bulk range 写入，无 nginx reload | `sudo ./waf-sklookup-demo bulk add -range 20000-20010` | ☐ |
| M2-5 | **30K fill**（M3 入口） | `./scripts/m3-fill-ports.sh 30000` → `list -count` ≈ 30000+demo 口；elapsed 可接受 | ☐ |
| M2-6 | **60K fill**（M3 入口） | `./scripts/m3-fill-ports.sh 60000` | ☐ |

M1/P1 `verify` / `close-port` / `open-port` 别名仍应可用。
