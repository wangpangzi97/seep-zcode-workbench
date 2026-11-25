# Seep ZCode Workbench — DSH Bundle

把 [`seep-zcode`](../../zcode) MCP 服务端接入 DeepSeek Harness（DSH）。

本 bundle 只做**接线**，不包含代码。真正的服务端在仓库的 `zcode/` 目录，通过 `cordis.patch.yml` 指过去。

## 挂载内容（64 个工具）

| 分组 | 数量 | 说明 |
|---|---|---|
| 本机工具链 | 26 | radare2 系列、jadx / apktool、Frida、tshark、PE 解析、工作流 |
| VM 工具封装 | 24 | capa / FLOSS / die / sigcheck / pe-sieve / yara / 7z / dnSpy / nmap / angr / oletools |
| VM 执行通道 | 6 | vmrun 执行命令、传文件、跑 VM 内 Python |
| GDB 内核调试 | 7 | 内存读写、寄存器、断点、反汇编 |
| 知识库 | 4 | 292 篇战术文档检索、清单、payload |

> 同一工具可能出现在多组统计中，实际唯一工具数为 64。

## 安装

### 前置

1. Python 3.11+，且 `import mcp` 可用
2. 仓库已克隆到任意目录（下文用 `<PATH_TO_REPO>` 表示）

```bash
python -c "import mcp; print('ok')"
```

### 步骤

**1. 把 bundle 放进 DSH 的 profile**

```bat
xcopy /E /I <PATH_TO_REPO>\dsh\seep-zcode-mcp %USERPROFILE%\.dsh\profiles\desktop\node_modules\@local\seep-zcode-mcp
```

**2. 编辑 `cordis.patch.yml`，把占位符换成真实值**

| 占位符 | 换成 |
|---|---|
| `<PATH_TO_PYTHON_WITH_MCP>` | 能 `import mcp` 的 python.exe 完整路径 |
| `<PATH_TO_REPO>` | 仓库根目录（`zcode/` 的上一级） |

**3. 注册到 profile 的 `package.json`**

```json
{
  "dsh": {
    "profile": {
      "bundles": [ "...", "@local/seep-zcode-mcp" ]
    }
  },
  "dependencies": {
    "@local/seep-zcode-mcp": "link:<PATH_TO_REPO>/dsh/seep-zcode-mcp"
  }
}
```

**4. 重启 DSH**

## 重要：DSH 会重写配置

DSH 的 plugin manager 在启动时会用自己的内存列表覆盖 `package.json`。

因此**修改 `bundles` 必须在 DSH 完全关闭时进行**，否则改动会被覆盖或还原。

## 关键配置语义

```yaml
failOnStartupError: false   # 连不上只记日志并持续重连
                            # true 会回滚 fiber，之后永不恢复（只能重启 DSH）
toolCallTimeoutMs: 900000   # 长任务（jadx 全量 / capa / angr / dnSpy）需要 15 分钟
```

服务端启动很快（实测约 0.7 秒），因为 VM 与 GDB 通道都是**按调用惰性连接**，
虚拟机没开机也不影响 DSH 启动。

## 配置工具路径

工具路径全部在 `zcode/mcp/tools.ini`，不需要改 bundle。

```bat
copy zcode\mcp\tools.ini.example zcode\mcp\tools.ini
```

`[vm]` 段留空占位符时，VM 相关工具会给出明确提示，本机工具和知识库照常可用。

## 技能

仓库的 `zcode/skills/` 下有 10 个技能，复制到 DSH 技能目录即可被发现：

```bat
xcopy /E /I <PATH_TO_REPO>\zcode\skills\* %USERPROFILE%\.dsh\skills\
```

## 验证

```
seep_status
```

应返回 radare2 / rabin2 / jadx / apktool / java 均为 Ready，知识库显示文档数。
