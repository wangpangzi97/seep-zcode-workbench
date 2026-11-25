# Seep ZCode Workbench

把本机逆向工具链、VMware 虚拟机调试、GDB 内核调试和逆向知识库，封装成 **64 个 MCP 工具**。

同一份 MCP 服务端，提供两种 Agent 的接入形态：

| 版本 | 目录 | 适用 Agent | 接入方式 |
|---|---|---|---|
| **ZCode 版** | [`zcode/`](zcode) | ZCode | 插件目录 + `plugin.json` |
| **DSH 版** | [`dsh/`](dsh) | DeepSeek Harness | bundle + `cordis.patch.yml` |

两者共用 `zcode/` 里的服务端代码 —— DSH 版只是接线层，不重复代码。

## 能力概览

| 分组 | 数量 | 说明 |
|---|---|---|
| 本机工具链 | 26 | radare2 系列、jadx / apktool、Frida、tshark、PE 解析、工作流 |
| VM 工具封装 | 24 | capa / FLOSS / die / sigcheck / pe-sieve / yara / 7z / dnSpy / nmap / angr / oletools |
| VM 执行通道 | 6 | vmrun 执行、传文件、跑 VM 内 Python |
| GDB 内核调试 | 7 | 内存读写、寄存器、断点、反汇编 |
| 知识库 | 4 | 292 篇战术文档检索、清单、payload |

核心特点：

- **纯 Python stdlib + `mcp`**，无其他第三方依赖
- **VM 与 GDB 通道按调用惰性连接** —— 虚拟机没开机也不影响启动
- **反汇编/反编译支持三档降噪** —— `full` / `branch|fold` / `summary`，直接控制上下文消耗
- **VM 内工具返回结构化结果** —— 不用自己解析 stdout

## 快速开始

### ZCode

```bat
xcopy /E /I zcode %USERPROFILE%\.zcode\cli\plugins\local\seep-zcode
copy %USERPROFILE%\.zcode\cli\plugins\local\seep-zcode\mcp\tools.ini.example ^
     %USERPROFILE%\.zcode\cli\plugins\local\seep-zcode\mcp\tools.ini
```

编辑 `tools.ini` 填工具路径，重启 ZCode，然后调用 `seep_doctor` 验证。

详细步骤见 [`zcode/README.md`](zcode/README.md)。

### DSH

```bat
xcopy /E /I dsh\seep-zcode-mcp %USERPROFILE%\.dsh\profiles\desktop\node_modules\@local\seep-zcode-mcp
```

编辑 bundle 里的 `cordis.patch.yml` 替换占位符，注册到 profile 的 `package.json`，重启 DSH。

详细步骤见 [`dsh/seep-zcode-mcp/docs/DETAIL.md`](dsh/seep-zcode-mcp/docs/DETAIL.md)。

## 前置条件

| 需要 | 必需性 | 说明 |
|---|---|---|
| Python 3.11+ | **必需** | 必须能 `import mcp` |
| radare2 | 推荐 | r2 系列工具依赖 |
| Java 17+ | 可选 | jadx / apktool 需要 |
| VMware + 虚拟机 | 可选 | VM 相关 30 个工具需要 |
| Frida / tshark | 可选 | 对应工具需要 |

验证 Python 环境：

```bat
python -c "import mcp; print('ok')"
```

## 配置

所有路径集中在 `zcode/mcp/tools.ini`：

```ini
[machine]
python = <PATH_TO_PYTHON_WITH_MCP>
java   = <PATH_TO_JAVA>

[paths]
jadx    = <PATH_TO_JADX>
radare2 = <PATH_TO_RADARE2>
ida     = <PATH_TO_IDA>

[vm]
host     = <YOUR_VM_IP>
user     = <YOUR_VM_USER>
password = <YOUR_VM_PASSWORD>
vmx      = <PATH_TO_YOUR_VMX>

[gdb]
host = 127.0.0.1
port = 8864
```

`[vm]` 段留占位符时，VM 相关工具会给出明确提示，本机工具与知识库照常可用 —— 不影响基础使用。

## lab 闸门

插件带一道 lab 闸门，默认关闭。只有输入 `lab：`（或 `实验：` / `enter lab`）才注入作战纪律。

仅提到 APK、破解、hook 不会激活。退出用 `退出实验`。

## 技能与知识库

- **10 个技能**：`softseep`（总控）、`apkseep`、`exe-reverse`、`webseep`、`radare2`、`ida-reverse`、`apk-reverse`、`reverse-engineering`、`client-license-validation-bypass`、`mcp-js-reverse-playbook`
- **292 篇知识库**：PE 逆向、APK 逆向、Web 攻防、CTF 实战案例、field journal

## 来源声明

技能文档与知识库来源于以下开源项目，在此致谢：

| 来源 | 授权 | 引用内容 |
|---|---|---|
| [angusdevgo/Seep-Reverse-Lab](https://github.com/angusdevgo/Seep-Reverse-Lab) | GPL-3.0 | 技能体系、知识库、lab 闸门设计、MCP 工具定义 |
| [LING71671/open-reverselab](https://github.com/LING71671/open-reverselab) | GPL-3.0 | 逆向知识库、field journal |
| [GeniusHu-tgty/Open-tgtylab](https://github.com/GeniusHu-tgty/Open-tgtylab) | GPL-3.0 | 安全研究实验室框架、信号路由协议 |
| [newliver666/apk-reverse](https://github.com/newliver666/apk-reverse) | MIT | 移动端逆向方法论 |
| [dabao1955/exe-reverse](https://codeberg.org/dabao1955/exe-reverse) | MIT | Windows PE 分析方法论 |

MCP 传输层基于 [Model Context Protocol](https://modelcontextprotocol.io/)（MIT）。

**本仓库的改动**：把上述能力移植到 ZCode / DSH 的插件形态，并新增 VMware 虚拟机执行通道、GDB 内核调试封装、VM 内工具结构化层。

## 授权

**GPL-3.0**，与上游 Seep-Reverse-Lab 一致。详见 [LICENSE](LICENSE)。

## 免责声明

仅供**已获授权的安全测试、逆向工程学习与 CTF 竞赛**使用。

使用前请确认对目标拥有合法测试授权。作者不对任何滥用行为承担责任。

涉及的 VMware、x64dbg、IDA Pro、Wireshark 等商业软件的授权合规，由使用者自行负责。
