#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 seep 仓库里的技能同步进插件的 skills/ 目录。

ZCode 通过扫描插件目录下的 `skills/`（每个子目录含 SKILL.md）来发现技能。
seep 的 `Tool/skill/` 下既有主技能也有 `safe-skills/` 的工具包，本脚本把两层
都展平到 `skills/` 一层（ZCode 不递归发现嵌套的 skill 目录）。

用法:
    python sync-skills.py [--seep-root <路径>] [--plugin-root <路径>] [--dry-run]
"""
import argparse
import os
import shutil
import sys
from pathlib import Path

DEFAULT_SEEP = Path(__file__).resolve().parent.parent.parent / "seep"
DEFAULT_PLUGIN = Path(__file__).resolve().parent.parent

# safe-skills 下的工具包也当成独立技能挂上
SAFE_TOOLKITS = {"apk-reverse", "ida-reverse", "mcp-js-reverse-playbook", "radare2", "reverse-engineering"}


def find_skills(skill_root: Path):
    """返回 [(技能目录, 是否来自 safe-skills)]。"""
    found = []
    if not skill_root.is_dir():
        return found
    for d in sorted(skill_root.iterdir()):
        if not d.is_dir():
            continue
        if d.name == "safe-skills":
            for sd in sorted(d.iterdir()):
                if sd.is_dir() and (sd / "SKILL.md").is_file():
                    found.append((sd, True))
        elif (d / "SKILL.md").is_file():
            found.append((d, False))
    return found


def read_frontmatter_name(skill_md: Path):
    """从 SKILL.md 的 YAML frontmatter 取 name，取不到就用目录名。"""
    try:
        text = skill_md.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    for line in text[3:end].splitlines():
        line = line.strip()
        if line.startswith("name:"):
            val = line.split(":", 1)[1].strip().strip("'\"")
            return val or None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seep-root", default=str(DEFAULT_SEEP))
    ap.add_argument("--plugin-root", default=str(DEFAULT_PLUGIN))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    seep_root = Path(args.seep_root)
    plugin_root = Path(args.plugin_root)
    src = seep_root / "Tool" / "skill"
    dst = plugin_root / "skills"

    if not src.is_dir():
        print("[ERROR] 未找到技能目录: %s" % src, file=sys.stderr)
        print("        先确认 seep 仓库已拉取（Tool/skill 应存在）", file=sys.stderr)
        return 2

    skills = find_skills(src)
    if not skills:
        print("[ERROR] 技能目录里没有找到任何 SKILL.md", file=sys.stderr)
        return 2

    print("源: %s" % src)
    print("目标: %s" % dst)
    print("发现 %d 个技能\n" % len(skills))

    if not args.dry_run:
        dst.mkdir(parents=True, exist_ok=True)

    ok = 0
    for skill_dir, from_safe in skills:
        name = read_frontmatter_name(skill_dir / "SKILL.md") or skill_dir.name
        target = dst / skill_dir.name
        tag = "safe" if from_safe else "main"

        # 大小统计
        total = sum(f.stat().st_size for f in skill_dir.rglob("*") if f.is_file())
        nfiles = sum(1 for f in skill_dir.rglob("*") if f.is_file())

        if args.dry_run:
            print("  [%s] %-34s %4d 文件 %7.1f KB  name=%s" % (
                tag, skill_dir.name, nfiles, total / 1024, name))
            ok += 1
            continue

        try:
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(skill_dir, target)
            print("  [%s] %-34s %4d 文件 %7.1f KB  -> skills/%s" % (
                tag, skill_dir.name, nfiles, total / 1024, skill_dir.name))
            ok += 1
        except Exception as e:
            print("  [FAIL] %s: %s" % (skill_dir.name, e))

    print("\n完成: %d/%d 个技能已同步" % (ok, len(skills)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
