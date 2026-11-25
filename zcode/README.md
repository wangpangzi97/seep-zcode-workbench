# Seep ZCode Workbench — ZCode 插件

把本机逆向工具链、VMware 虚拟机调试、GDB 内核调试和逆向知识库封装成 **64 个 MCP 工具**，供 ZCode 全自动调用。

## 它做什么

一个 MCP 服务端 + 10 个技能 + 一道 lab 闸门，让你用大白话驱动逆向流程，不必手动切工具。

```
你: lab：分析这个样本，看看有没有客户端鉴权
      ↓
Agent 自动: seep_auto_triage → seep_kb_search → seep_vm_capa
            → 定位分支 → seep_vm_die → 出报告
```

## 工具清单

### 本机工具链（26 个）

| 类别 | 工具 |
|---|---|
| **radare2 系列** | `seep_r2_info` 架构/安全机制、`seep_r2_cmd` 任意命令、`seep_r2_functions` 函数列表、`seep_r2_strings` 字符串、`seep_r2_disasm` 反汇编、`seep_r2_decompile` 反编译、`seep_r2_xrefs` 交叉引用、`seep_r2_diff` 差分、`seep_r2_asm` 汇编/反汇编 |
| **APK** | `seep_apk_info` 结构解析（免 Java）、`seep_apk_decompile` jadx、`seep_apk_unpack` apktool、`seep_apk_smali_search` 代码搜索、`seep_apk_gen_hook` Hook 脚本生成 |
| **其他** | `seep_jadx_decompile`、`seep_apktool_decode` / `_build`、`seep_frida_devices` / `_ps` / `_run_script`、`seep_tshark_capture` / `_read`、`seep_pe_info`、`seep_doctor`、`seep_run_command` |
| **工作流** | `seep_status`、`seep_task_init`、`seep_auto_triage`、`seep_gen_security_report`、`seep_ida_status` |

`seep_r2_disasm` 和 `seep_r2_decompile` 支持三档降噪模式，直接控制上下文消耗：

- `full` — 完整输出
- `branch` / `fold` — 只留控制流骨架（约省 60%）
- `summary` — 只给函数签名与调用关系（最省）

### VM 工具封装（24 个）

调用虚拟机内**没有自带 MCP** 的分析工具，返回结构化结果：

| 工具 | 底层 | 返回 |
|---|---|---|
| `seep_vm_triage` | PE + die + sigcheck + capa | 四合一画像 |
| `seep_vm_capa` | capa | `tactics` / `techniques` / `attack_ids` |
| `seep_vm_floss` | FLOSS | 静态/解码/栈字符串 |
| `seep_vm_die` | Detect It Easy | `compiler` / `packer` / `protector` |
| `seep_vm_sigcheck` | Sigcheck | 签名状态 / 发布者 / 哈希 |
| `seep_vm_pesieve` | pe-sieve | 注入 / hook / 内存补丁检测 |
| `seep_vm_yara` / `_strings` / `_upx` / `_7z` | — | 规则扫描 / 字符串 / 壳 / 解包 |
| `seep_vm_dotnet` | dnSpy / de4dot | .NET 反编译 / 去混淆 |
| `seep_vm_apk` | apktool | APK 解包 |
| `seep_vm_nmap` / `_tshark` | — | 端口服务 / 抓包 |
| `seep_vm_pe_analyze` | pefile + lief | 节区/熵/导入/哈希 |
| `seep_vm_angr` | angr | 控制流图 |
| `seep_vm_oletools` | oletools | Office 宏提取 |

### VM 执行通道（6 个）

`seep_vm_run` 执行命令、`seep_vm_python` 跑 VM 内 Python、`seep_vm_put_file` / `seep_vm_get_file` 传文件、`seep_vm_list_dir` 列目录、`seep_vm_start` 启动程序。

### GDB 内核调试（7 个）

直连 VMware 的 GDB stub（`127.0.0.1:8864`），**不需要虚拟机登录凭据**：

| 工具 | 作用 |
|---|---|
| `seep_vm_kernel_state` | 停止原因 + 全部寄存器 |
| `seep_vm_kernel_regs` | 读指定寄存器 |
| `seep_vm_read_mem` | 读内核/用户内存 |
| `seep_vm_write_mem` | 写内存（带回读校验） |
| `seep_vm_kernel_disasm` | 读内存后反汇编 |
| `seep_vm_breakpoint` | 下/移断点、继续执行 |
| `seep_vm_detach` | 说明连接生命周期 |

前提：虚拟机 `.vmx` 里设置 `debugStub.listen.guest64 = "TRUE"`。

### 知识库（4 个）

`seep_kb_search` 全文检索、`seep_kb_read` 读文档、`seep_kb_checklist` 战术清单、`seep_kb_payloads` Payload 库。

内置 292 篇战术文档（PE 逆向、APK 逆向、Web 攻防、CTF 实战案例）。

## lab 闸门

默认关闭。只有输入 `lab：`（或 `实验：` / `enter lab`）才注入作战纪律。

提到 APK、破解、hook 都不会激活 —— 这是刻意的安全边界。退出用 `退出实验`。

## 安装

### 前置

| 需要 | 说明 |
|---|---|
| Python 3.11+ | **必须能 `import mcp`** |
| ZCode | 已安装并运行 |
| Java 17+ | jadx / apktool 需要（可选） |
| radare2 | 可选，缺失时 r2 系列工具会报错提示 |

先验证 Python：

```bat
python -c "import mcp; print('ok')"
```

若报 `ModuleNotFoundError`，先装依赖：

```bat
python -m pip install mcp
```

### 步骤

**1. 放置插件**

把整个目录复制到 ZCode 插件目录：

```bat
xcopy /E /I zcode %USERPROFILE%\.zcode\cli\plugins\local\seep-zcode
```

（也可以放在任意位置，后续只需改 `plugin.json` 里的路径。）

**2. 配置工具路径**

```bat
copy %USERPROFILE%\.zcode\cli\plugins\local\seep-zcode\mcp\tools.ini.example ^
     %USERPROFILE%\.zcode\cli\plugins\local\seep-zcode\mcp\tools.ini
```

编辑 `tools.ini`，按注释填写：

- `[machine]` — Python 与 Java 的完整路径
- `[paths]` — jadx / apktool / radare2 / IDA 等工具路径
- `[vm]` — 虚拟机配置（不用可留占位符）
- `[gdb]` — GDB stub 地址，默认 `127.0.0.1:8864` 通常不用改

**3. 注册到 ZCode**

编辑 `%USERPROFILE%\.zcode\cli\config.json`：

```json
{
  "plugins": {
    "enabledPlugins": {
      "seep-zcode@local": true
    }
  }
}
```

并在 `%USERPROFILE%\.zcode\cli\plugins\installed_plugins.json` 的 `plugins` 数组里加一条：

```json
{
  "id": "seep-zcode@local",
  "name": "seep-zcode",
  "marketplace": "local",
  "version": "1.0.0",
  "installPath": "<安装路径>\\seep-zcode",
  "scope": "user",
  "source": { "source": "local", "type": "directory", "path": "<安装路径>\\seep-zcode" }
}
```

**4. 重启 ZCode**

MCP 是会话启动时握手的，必须完全退出重开。

**5. 验证**

在对话框里调用：

```
seep_doctor
```

应列出各工具的 READY / MISSING 状态。

### 可选：挂载虚拟机调试器 MCP

若虚拟机里跑着 x64dbg / IDA 的 MCP 服务，可在 ZCode 的 MCP 配置里另加 HTTP 端点：

```json
{
  "mcp": {
    "servers": {
      "x64dbg_vm": {
        "type": "http",
        "url": "http://<YOUR_VM_IP>:3000/mcp",
        "http_headers": { "Authorization": "Bearer <YOUR_TOKEN>" },
        "enabled": true,
        "tool_timeout_sec": 300
      }
    }
  }
}
```

## 配置说明

所有路径都在 `mcp/tools.ini`，改一处即可：

```ini
[machine]
python = <PATH_TO_PYTHON_WITH_MCP>
java   = <PATH_TO_JAVA>

[paths]
jadx    = <PATH_TO_JADX>
radare2 = <PATH_TO_RADARE2>

[vm]
host     = <YOUR_VM_IP>
user     = <YOUR_VM_USER>
password = <YOUR_VM_PASSWORD>
vmx      = <PATH_TO_YOUR_VMX>

[gdb]
host = 127.0.0.1
port = 8864
```

`[vm]` 留占位符时，VM 相关工具会给出明确提示，本机工具与知识库照常可用。

## 常见问题

**Q: MCP 工具一个都看不到**
完全退出 ZCode 再重开（不是新开标签页）。MCP 在会话启动时握手。

**Q: `seep_doctor` 报 jadx DEGRADED**
`JAVA_HOME` 没设置。工具已自动处理 PATH，若仍失败请检查 `tools.ini` 的 `java` 路径。

**Q: r2 系列工具报错**
`tools.ini` 的 `[paths]` 里 radare2 路径不对，或系统 PATH 里没有 radare2。

**Q: VM 工具报「虚拟机未配置」**
`[vm]` 段还是占位符。不打算用虚拟机可以忽略。

## 目录结构

```
zcode/
├── .zcode-plugin/plugin.json   # 插件清单（MCP + hook + 技能注册）
├── mcp/
│   ├── server.py               # MCP 服务端（64 个工具）
│   ├── upstream_tools.py       # radare2 降噪 / apk / 工作流
│   ├── vmtools.py              # VM 内工具结构化封装
│   ├── vmrun.py                # vmrun 执行通道
│   ├── gdbstub.py              # GDB 内核调试客户端
│   ├── tools.ini               # 工具路径配置
│   └── tools.ini.example       # 配置模板
├── hooks/lab-gate.js           # lab 闸门
├── skills/                     # 10 个技能
├── discipline/SYSTEM.md        # 作战纪律正文
├── kb/                         # 292 篇知识库
└── scripts/                    # 技能同步 / 适配脚本
```

## 来源声明

本项目的技能文档与知识库来源于以下开源项目，在此致谢：

| 来源 | 授权 | 引用内容 |
|---|---|---|
| [angusdevgo/Seep-Reverse-Lab](https://github.com/angusdevgo/Seep-Reverse-Lab) | GPL-3.0 | `skills/` 技能体系、`kb/` 知识库、lab 闸门设计、`seep_mcp_server.py` 的工具定义与实现思路 |
| [LING71671/open-reverselab](https://github.com/LING71671/open-reverselab) | GPL-3.0 | 逆向知识库、field journal |
| [GeniusHu-tgty/Open-tgtylab](https://github.com/GeniusHu-tgty/Open-tgtylab) | GPL-3.0 | 安全研究实验室框架、信号路由协议 |
| [newliver666/apk-reverse](https://github.com/newliver666/apk-reverse) | MIT | 移动端逆向方法论与验证测试套件 |
| [dabao1955/exe-reverse](https://codeberg.org/dabao1955/exe-reverse) | MIT | Windows PE 分析方法论 |

MCP 传输层基于 [Model Context Protocol](https://modelcontextprotocol.io/)（Anthropic，MIT）。

**本仓库的改动**：将上述能力移植到 ZCode 的插件形态，并新增 VMware 虚拟机执行通道、GDB 内核调试封装、VM 内工具结构化层。

## 授权

本项目遵循 **GPL-3.0**（与上游 Seep-Reverse-Lab 一致）。

## 免责声明

本项目仅用于**已获授权的安全测试、逆向工程学习与 CTF 竞赛**。

使用前请确认你对目标拥有合法测试授权。作者不对任何滥用行为承担责任。

工具中涉及的 VMware、x64dbg、IDA Pro、Wireshark 等软件的授权与合规使用，由使用者自行负责。
