#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成插件安装包：把 ${CLAUDE_PLUGIN_ROOT} 解析成绝对路径，产出可直接投放的版本。"""
import json
import os
import shutil
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent
STAGE = SRC / "dist" / "seep-zcode"


def copy_tree(src: Path, dst: Path):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(
        src, dst,
        ignore=shutil.ignore_patterns("dist", "__pycache__", "*.pyc", ".git"),
    )


def main():
    print("staging ->", STAGE)
    STAGE.parent.mkdir(parents=True, exist_ok=True)
    copy_tree(SRC, STAGE)

    # 解析 plugin.json 里的 ${CLAUDE_PLUGIN_ROOT}
    pj = STAGE / ".zcode-plugin" / "plugin.json"
    data = json.loads(pj.read_text(encoding="utf-8"))
    root_posix = str(STAGE).replace("\\", "/")

    for name, srv in (data.get("mcpServers") or {}).items():
        srv["args"] = [a.replace("${CLAUDE_PLUGIN_ROOT}", root_posix) for a in srv.get("args", [])]
        srv["command"] = srv["command"].replace("${CLAUDE_PLUGIN_ROOT}", root_posix)

    for evt, groups in (data.get("hooks") or {}).items():
        for g in groups:
            for h in g.get("hooks", []):
                if "args" in h:
                    h["args"] = [a.replace("${CLAUDE_PLUGIN_ROOT}", root_posix) for a in h["args"]]
                if "command" in h:
                    h["command"] = h["command"].replace("${CLAUDE_PLUGIN_ROOT}", root_posix)

    pj.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print("resolved plugin.json ->")
    print(json.dumps(data, indent=2, ensure_ascii=False)[:1200])

    n = sum(1 for _ in STAGE.rglob("*") if _.is_file())
    size = sum(f.stat().st_size for f in STAGE.rglob("*") if f.is_file())
    print("\n文件数: %d  大小: %.2f MB" % (n, size / 1048576))
    return 0


if __name__ == "__main__":
    sys.exit(main())
