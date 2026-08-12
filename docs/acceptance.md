# waf-sklookup-demo QA 验收报告 / Acceptance Report

- **日期 (Asia/Shanghai)**: 2026-08-13 00:43 CST
- **执行人**: QA on shared box (`box` uid 1000, sudo OK)
- **项目路径**: `/workspace/waf-sklookup-demo`
- **总体结论 / Overall**: **PASS**

## 环境 / Environment

| Item | Value |
|------|--------|
| Kernel | `6.12.94+` (≥5.9, sk_lookup OK) |
| Go | `go1.24.4 linux/amd64` |
| clang | Debian clang 19.1.7 |
| libbpf headers | present (`/usr/include/bpf`) |
| bpftool | v7.5.0 (`/usr/sbin/bpftool`, package installed) |
| sudo / CAP_BPF | passwordless sudo available; demo ran as root |

### bpftool sk_lookup

```text
$ sudo bpftool feature list_builtins prog_types | rg sk_lookup
sk_lookup

$ sudo bpftool feature | rg 'program_type sk_lookup'
eBPF program_type sk_lookup is available
```

Unprivileged `bpftool feature` without caps fails full probe with:
`Error: missing CAP_SYS_ADMIN, CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON...` — use sudo.

## 验收清单 / Checklist

| # | 项 | 结果 | 证据摘要 |
|---|----|------|----------|
| 1 | `go generate` + `go build` 成功 | **PASS** | generate 写出 `dispatch_bpfel.go/.o`；`CGO_ENABLED=0 go build -o waf-sklookup-demo .` 成功 |
| 2 | 用户态仅监听真实端口 18080；18081/18082/65500 无 listen | **PASS** | `ss -lntp` 仅见 `127.0.0.1:18080` |
| 3 | curl 真实端口 + 导向端口均 HTTP 200 / demo OK | **PASS** | 四端口均返回 `sk_lookup demo OK` + HTTP 200 |
| 4 | 负向：从 map 删除端口或停止 BPF 后导向端口失败 | **PASS** | 删除 `open_ports` 中 18081 后该端口 connect fail；其余仍 200；进程停止后导向端口全 fail |
| 5 | 记录内核版本、bpftool sk_lookup、失败与最小修复建议 | **PASS** | 见上文环境 + 下文 Fixes |

## 关键命令 / Key commands

```bash
# env fix (box): missing /usr/include/asm multiarch symlink
sudo ln -sfn x86_64-linux-gnu/asm /usr/include/asm

cd /workspace/waf-sklookup-demo
go generate ./...
CGO_ENABLED=0 go build -o waf-sklookup-demo .

sudo ./waf-sklookup-demo -listen 127.0.0.1:18080 -ports 18081,18082,65500
```

### #2 ss（仅真实端口）

```text
LISTEN 0 4096 127.0.0.1:18080 0.0.0.0:*
# 无 18081 / 18082 / 65500 userspace listen
```

### #3 curl

```text
http://127.0.0.1:18080/  -> 200  sk_lookup demo OK
http://127.0.0.1:18081/  -> 200  sk_lookup demo OK  (http_local_addr=127.0.0.1:18081)
http://127.0.0.1:18082/  -> 200  sk_lookup demo OK
http://127.0.0.1:65500/  -> 200  sk_lookup demo OK
```

### #4 负向：从 BPF map 删除导向端口

```bash
sudo bpftool map dump name open_ports
# keys: 18081, 18082, 65500

# 18081 = 0x46a1 → little-endian key bytes a1 46
sudo bpftool map delete name open_ports key hex a1 46

curl -sS --max-time 3 http://127.0.0.1:18081/   # FAIL: curl exit 7 (connection refused / not connect)
curl -sS --max-time 3 http://127.0.0.1:18082/   # still 200
curl -sS --max-time 3 http://127.0.0.1:18080/   # still 200
curl -sS --max-time 3 http://127.0.0.1:65500/   # still 200
```

停止进程后导向端口亦无法连接（BPF detach + listener 关闭）。

## 失败与最小修复 / Failures & minimal fixes applied

Acceptance 过程中为使构建可跑，做了 **最小产品改动**（非功能逻辑）：

1. **`dispatch.bpf.c`**: 增加 `#include <linux/in.h>` —— 否则 `IPPROTO_TCP` undeclared，`go generate` 失败。
2. **`loader.go`**: 删除未使用的 `"github.com/cilium/ebpf"` import —— 否则在 `CGO_ENABLED=0` 构建时报 unused import。

环境侧（非产品代码）：

3. **`/usr/include/asm` 缺失**: Debian multiarch 头在 `x86_64-linux-gnu/asm`；创建 symlink 后 clang 可找到 `asm/types.h`。
4. **必须 `CGO_ENABLED=0 go build`**: 包目录内 `dispatch.bpf.c` 在默认 CGO 下触发 `C source files not allowed when not using cgo or SWIG`。建议后续在 Makefile/`run.sh` 写明 `CGO_ENABLED=0`，或把 `.bpf.c` 移出 main package 目录。

## 清理 / Cleanup

已 `kill -9` 本次启动的 demo 进程；`ss` 确认 18080/18081/18082/65500 无残留监听。

## 总评 / Verdict

**PASS** — 五项验收均通过；sk_lookup 导向行为符合 README（单真实 bind + map 控端口 + 删 map 即关端口）。建议把 Makefile 默认加上 `CGO_ENABLED=0`，避免他人裸 `go build` 踩坑。
