#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为 ZCode 适配 seep 技能里的框架专属引用。

seep 的技能原本面向 OpenCode / 自带 MCP 的环境，直接搬进 ZCode 有三类不匹配：

  1. `<WORKSPACE>` 占位符 —— OpenCode 的路径模板，ZCode 不展开它。
     改成说明性的相对路径指引。
  2. `idapro_*` 工具前缀 —— 本机 ZCode 挂的是 `ida` 服务器，
     实际工具名是 `mcp__ida__*`。
  3. `scripts/*.ps1` 的硬编码调用方式 —— 改为插件内相对路径。

本脚本就地改写，幂等（重复跑不会叠加）。
用法:
    python adapt-skills.py [--plugin-root <路径>] [--dry-run]
"""
import argparse
import re
import sys
from pathlib import Path

DEFAULT_PLUGIN = Path(__file__).resolve().parent.parent

# (正则, 替换) —— 按顺序应用
RULES = [
    # 1. <WORKSPACE> 占位符
    (re.compile(r"<WORKSPACE>[\\/]Tool[\\/]skills[\\/]"), "skills/"),
    (re.compile(r"<WORKSPACE>[\\/]Tool[\\/]skill[\\/]"), "skills/"),
    (re.compile(r"<WORKSPACE>[\\/]"), ""),
    (re.compile(r"<WORKSPACE>"), "<plugin-root>"),

    # 2. idapro_* -> mcp__ida__*（ZCode 暴露 MCP 工具的命名规则）
    (re.compile(r"\bidapro_(?=[a-z])"), "mcp__ida__"),
]

# ida-reverse 技能在本机需要额外说明：工具集不同
IDA_REVERSE_NOTICE = """
> **ZCode 适配说明（重要）**
>
> 本技能原文面向 `idapro` MCP 服务端（mrexodia/ida-pro-mcp，72 个 `idapro_*` 工具）。
> 本机 ZCode 挂载的是 **Hex-Rays 官方 `ida` 服务端**（`ida-domain` API），
> 工具名前缀为 `mcp__ida__*`，**不是** `idapro_*`。
>
> 对照关系：
>
> | 原技能写法 | 本机可用写法 |
> |---|---|
> | `idapro_decompile(addr)` | `mcp__ida__execute_python` 里调 `db.pseudocode.get_text(ea)` |
> | `idapro_disasm(addr)` | `mcp__ida__execute_python` 里 `disasm()` |
> | `idapro_xrefs_to(addrs)` | `mcp__ida__execute_python` 里查 xrefs |
> | `idapro_survey_binary()` | `mcp__ida__execute_python` 统计函数/字符串/导入 |
> | `idapro_rename(...)` | `mcp__ida__execute_python` 调 `db.functions.set_name` |
> | `idapro_py_eval(code)` | `mcp__ida__execute_python(code=...)` |
>
> 另：`scripts/start.ps1` / `scripts/open.ps1` 是给 **idalib-mcp** 用的，
> 本机用的是官方 `ida-mcp`，打开数据库请直接用 `mcp__ida__open_database(path=...)`。
>
> 下文所有 `scripts/*.ps1` 的调用方式仅供参考，实际执行请用 MCP 工具。
"""


def adapt_skill_md(f: Path, text: str) -> str:
    """对 SKILL.md 做通用规则之外的针对性补充。"""
    if f.parent.name != "ida-reverse":
        return text
    marker = "ZCode 适配说明（重要）"
    if marker in text:
        return text  # 已注入过，幂等
    # 插在 frontmatter 之后、正文第一个标题之前
    end = text.find("\n---", 3)
    if end == -1:
        return text
    insert_at = end + 4
    return text[:insert_at] + "\n" + IDA_REVERSE_NOTICE + text[insert_at:]

# 只对这些文件类型做改写
TARGET_SUFFIXES = {".md", ".ps1", ".py", ".json", ".js", ".txt", ".cmd", ".bat"}

# 顶层 README 之类的说明不要改
SKIP_NAMES = {"CHANGELOG.md"}


def adapt_text(text):
    original = text
    for pattern, repl in RULES:
        text = pattern.sub(repl, text)
    return text, text != original


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin-root", default=str(DEFAULT_PLUGIN))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    root = Path(args.plugin_root)
    skills = root / "skills"
    if not skills.is_dir():
        print("[ERROR] 找不到 %s" % skills, file=sys.stderr)
        return 2

    changed = []
    scanned = 0
    for f in skills.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in TARGET_SUFFIXES:
            continue
        if f.name in SKIP_NAMES:
            continue
        scanned += 1
        try:
            text = f.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as e:
            print("  [skip] %s: %s" % (f, e))
            continue
        new, did = adapt_text(text)
        if f.name == "SKILL.md":
            injected = adapt_skill_md(f, new)
            if injected != new:
                new, did = injected, True
        if not did:
            continue
        n_changes = sum(1 for a, b in zip(text.splitlines(), new.splitlines()) if a != b)
        # 行数可能变化，用正则命中数估算
        changed.append((f.relative_to(root), n_changes))
        if not args.dry_run:
            f.write_text(new, encoding="utf-8", newline="\n")

    print("扫描 %d 个文件，需要改写 %d 个\n" % (scanned, len(changed)))
    for rel, n in changed[:40]:
        print("  %s" % rel)
    if len(changed) > 40:
        print("  ... 另有 %d 个" % (len(changed) - 40))

    if args.dry_run:
        print("\n(dry-run，未写盘)")
    else:
        print("\n改写完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
