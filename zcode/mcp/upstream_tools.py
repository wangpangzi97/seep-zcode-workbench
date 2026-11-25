#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""seep 上游工具集（从 ReverseLab / seep-kit 合并）

这些工具原本在旧的 `seep-kit/Tool/mcp/seep_mcp_server.py` 里，
DSH 之前挂的就是那个服务。合并进来的原因：它的能力比本插件早期的简化版更强：

  - r2 系列支持 output_mode（full/branch/summary）上下文降噪
  - xrefs 有分页与统计摘要
  - apk 系列：APK 结构原生解析、smali 正则扫描、Hook 脚本生成
  - 工作流：task_init / auto_triage / gen_security_report

路径解析统一走本插件的 resolve_tool()，不再依赖"内置工具链"目录，
所以本机已有的 jadx / radare2 / apktool 能直接被这些工具用上。
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# 从宿主 server.py 注入的依赖（避免循环导入，用 set_context 注入）
# ---------------------------------------------------------------------------
_CTX: Dict[str, Any] = {}


def set_context(**kw):
    """由 server.py 注入：resolve_tool / run / KB_DIR / BASE_DIR 等。"""
    _CTX.update(kw)


def _resolve(section: str, key: str) -> Optional[str]:
    fn = _CTX.get("resolve_tool")
    return fn(section, key) if fn else None


def _run(cmd: List[str], timeout: int = 60, raw: bool = False) -> str:
    """执行命令并返回清洗后的输出（r2 的 ANSI 已剥离）。

    raw=True 时不套用宿主 run() 的输出截断 —— 解析 JSON 必须拿完整文本，
    否则会在 40000 字符处被切断导致 JSONDecodeError。
    """
    fn = _CTX.get("run")
    if fn:
        r = fn(cmd, timeout=timeout, limit=None if raw else MAX_OUT_CAP)
        out = (r.get("stdout") or "")
        err = (r.get("stderr") or "")
        if not r.get("ok") and not out:
            return "[ERROR code %s]: %s" % (r.get("code"), err[:500])
        text = out + ("\n[STDERR]: " + err if out.strip() and err.strip() else "")
        return _clean(text).strip()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
        out = (p.stdout or "")
        err = (p.stderr or "")
        if p.returncode != 0 and not out.strip():
            return "[ERROR code %s]: %s" % (p.returncode, err[:500])
        text = out + ("\n[STDERR]: " + err if out.strip() and err.strip() else "")
        return _clean(text).strip()
    except subprocess.TimeoutExpired:
        return "[ERROR]: 命令超时（%ds）" % timeout
    except Exception as e:
        return "[ERROR]: %s" % e


MAX_OUT_CAP = 40000


_ANSI = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _clean(text: str) -> str:
    return _ANSI.sub("", text or "")


def _kb_dir() -> str:
    return _CTX.get("KB_DIR") or ""


def _base_dir() -> str:
    return _CTX.get("BASE_DIR") or os.getcwd()


def _r2_exe():
    return _resolve("paths", "radare2")


def _rabin2():
    return _resolve("paths", "rabin2")


def _radiff2():
    return _resolve("paths", "radiff2")


def _rasm2():
    return _resolve("paths", "rasm2")


def _jadx():
    return _resolve("paths", "jadx")


def _apktool_jar():
    return _resolve("paths", "apktool")


def _java():
    return _CTX.get("JAVA_EXE") or _resolve("machine", "java")


# ---------------------------------------------------------------------------
# 1. 状态
# ---------------------------------------------------------------------------
def status() -> str:
    """检查工具链状态。"""
    java = _java()
    java_detail = "未找到（jadx/apktool 需要 JDK）"
    if java and os.path.isfile(java):
        java_detail = _run([java, "-version"], timeout=25).splitlines()[:1]
        java_detail = java_detail[0] if java_detail else java

    r2 = _r2_exe()
    r2_ver = _run([r2, "-v"], timeout=25).splitlines()[:1] if r2 else []
    kb = _kb_dir()
    kb_docs = len(glob.glob(os.path.join(kb, "**", "*.md"), recursive=True)) if kb and os.path.isdir(kb) else 0

    return json.dumps({
        "name": "seep-zcode",
        "base_directory": _base_dir(),
        "components": {
            "radare2": {"status": "Ready" if r2 else "Missing",
                        "path": r2 or "", "version": (r2_ver[0] if r2_ver else "")},
            "rabin2": {"status": "Ready" if _rabin2() else "Missing", "path": _rabin2() or ""},
            "jadx": {"status": "Ready" if _jadx() else "Missing", "path": _jadx() or ""},
            "apktool": {"status": "Ready" if _apktool_jar() else "Missing", "path": _apktool_jar() or ""},
            "java": {"status": "Ready" if java else "Missing", "detail": java_detail},
            "knowledge_base": {"status": "Ready (%d docs)" % kb_docs if kb_docs else "Missing",
                               "path": kb},
        },
    }, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# 2. radare2 系列
# ---------------------------------------------------------------------------
def r2_info(binary_path: str) -> str:
    """提取二进制关键元信息（架构/位数/安全机制）。"""
    if not os.path.isfile(binary_path):
        return "[ERROR]: 文件不存在: %s" % binary_path
    rabin2 = _rabin2()
    if not rabin2:
        return "[ERROR]: rabin2 不可用"
    return _run([rabin2, "-I", os.path.abspath(binary_path)])


def r2_cmd(binary_path: str, command: str, analyze: bool = True, timeout: int = 90) -> str:
    """执行任意 radare2 命令。"""
    if not os.path.isfile(binary_path):
        return "[ERROR]: 文件不存在: %s" % binary_path
    r2 = _r2_exe()
    if not r2:
        return "[ERROR]: radare2 不可用"
    full = ("aaa; " + command) if analyze else command
    return _run([r2, "-q", "-e", "scr.color=0", "-c", full,
                 os.path.abspath(binary_path)], timeout=timeout)


def r2_strings(binary_path: str, filter_text: str = "", all_sections: bool = False,
               limit: int = 100) -> str:
    """提取字符串，支持关键词过滤与全段检索。"""
    if not os.path.isfile(binary_path):
        return "[ERROR]: 文件不存在: %s" % binary_path
    rabin2 = _rabin2()
    if not rabin2:
        return "[ERROR]: rabin2 不可用"
    out = _run([rabin2, "-zz" if all_sections else "-z",
                os.path.abspath(binary_path)])
    lines = out.splitlines()
    if filter_text:
        pat = filter_text.lower()
        head = lines[:2] if len(lines) >= 2 else []
        matched = [l for l in lines[2:] if pat in l.lower()]
        res = head + matched[:limit]
        if len(matched) > limit:
            res.append("... [截断: 显示 %d/%d 条]" % (limit, len(matched)))
        return "\n".join(res)
    res = lines[:limit]
    if len(lines) > limit:
        res.append("... [截断: 显示 %d/%d 条]" % (limit, len(lines)))
    return "\n".join(res)


def r2_functions(binary_path: str, filter_name: str = "", limit: int = 100) -> str:
    """列出函数 / 符号。"""
    if not os.path.isfile(binary_path):
        return "[ERROR]: 文件不存在: %s" % binary_path
    r2 = _r2_exe()
    if not r2:
        return "[ERROR]: radare2 不可用"
    out = _run([r2, "-q", "-e", "scr.color=0", "-c", "aaa; afl",
                os.path.abspath(binary_path)], timeout=120)
    lines = [l for l in out.splitlines()
             if l.strip() and not l.startswith(("INFO:", "WARN:"))]
    if filter_name:
        pat = filter_name.lower()
        hits = [l for l in lines if pat in l.lower()]
        res = hits[:limit]
        if len(hits) > limit:
            res.append("... [截断: 显示 %d/%d 个函数]" % (limit, len(hits)))
        return "\n".join(res) or "[无匹配函数]"
    res = lines[:limit]
    if len(lines) > limit:
        res.append("... [截断: 显示 %d/%d 个函数]" % (limit, len(lines)))
    return "\n".join(res)


BRANCH_KW = ("cmp ", "test ", "je ", "jne ", "jz ", "jnz ", "jb ", "jbe ",
             "ja ", "jae ", "jl ", "jle ", "jg ", "jge ", "jmp ", "call ",
             "ret", "jcc", "cbz ", "cbnz ", "bl ", "bne ", "beq ")


def r2_disasm(binary_path: str, target: str = "main", lines: int = 60,
              output_mode: str = "full", limit_tokens: int = 0) -> str:
    """反汇编，支持 full / branch / summary 三档降噪。

    Args:
        output_mode: full 完整 / branch 仅控制流 / summary 仅统计
    """
    r2 = _r2_exe()
    if not r2:
        return "[ERROR]: radare2 不可用"
    if not os.path.isfile(binary_path):
        return "[ERROR]: 文件不存在: %s" % binary_path
    path = os.path.abspath(binary_path)
    mode = (output_mode or "full").lower()

    if mode == "summary":
        info = _run([r2, "-q", "-e", "scr.color=0", "-c", "aaa; afi @ %s" % target, path], timeout=90)
        xto = _run([r2, "-q", "-e", "scr.color=0", "-c", "axt @ %s" % target, path], timeout=90)
        xfrom = _run([r2, "-q", "-e", "scr.color=0", "-c", "axf @ %s" % target, path], timeout=90)
        return ("[反汇编 SUMMARY 模式]\nTarget: %s\n"
                "--- 函数信息 (afi) ---\n%s\n"
                "--- 调用方 (axt) ---\n%s\n"
                "--- 被调用 (axf) ---\n%s\n"
                "提示: 用 output_mode='branch' 或 'full' 看指令级细节。"
                % (target, info[:900], xto[:600], xfrom[:600]))

    out = _run([r2, "-q", "-e", "scr.color=0", "-c", "aaa; pdf @ %s" % target, path], timeout=90)
    olines = [l for l in out.splitlines() if l.strip() and not l.startswith(("INFO:", "WARN:"))]
    if not olines:
        out = _run([r2, "-q", "-e", "scr.color=0", "-c", "pd %d @ %s" % (lines, target), path], timeout=90)
        olines = [l for l in out.splitlines() if l.strip() and not l.startswith(("INFO:", "WARN:"))]

    if mode == "branch":
        kept = [l for l in olines if any(k in l.lower() for k in BRANCH_KW)]
        header = ("[反汇编 BRANCH 模式 — 仅控制流骨架，已滤掉 %d/%d 行纯数据指令]\n"
                  "Target: %s | 保留 %d 行\n" % (len(olines) - len(kept), len(olines), target, len(kept)))
        result = header + "\n".join(kept)
    else:
        result = "\n".join(olines)

    if limit_tokens and len(result) > limit_tokens:
        result = result[:limit_tokens] + "\n... [截断于 %d 字符]" % limit_tokens
    return result or "[反汇编为空或符号未找到]"


def r2_decompile(binary_path: str, target: str = "main", output_mode: str = "full",
                 limit_tokens: int = 8000) -> str:
    """反编译为伪代码，支持 full / fold / summary 三档。"""
    r2 = _r2_exe()
    if not r2:
        return "[ERROR]: radare2 不可用"
    if not os.path.isfile(binary_path):
        return "[ERROR]: 文件不存在: %s" % binary_path
    path = os.path.abspath(binary_path)
    mode = (output_mode or "full").lower()

    if mode == "summary":
        out = _run([r2, "-q", "-e", "scr.color=0",
                    "-c", "aaa; afi @ %s; axf @ %s" % (target, target), path], timeout=90)
        return "[反编译 SUMMARY 模式 — 仅函数签名与调用关系]\nTarget: %s\n%s\n提示: 用 'fold' 或 'full' 看伪代码。" % (
            target, out[:1200])

    out = _run([r2, "-q", "-e", "scr.color=0", "-c", "aaa; pdc @ %s" % target, path], timeout=120)
    olines = [l for l in out.splitlines() if l.strip() and not l.startswith(("INFO:", "WARN:"))]

    if mode == "fold":
        def keep(line: str) -> bool:
            s = line.strip()
            kws = ("if ", "else", "switch", "case ", "return", "while ", "for ",
                   "do {", "goto ", "break", "continue", "call ", "(", "->")
            return any(k in s for k in kws) or s.startswith("//")
        folded = [l for l in olines if keep(l)]
        pct = int((len(olines) - len(folded)) / max(len(olines), 1) * 100)
        result = ("[反编译 FOLD 模式 — 已折叠 %d/%d 行纯赋值/计算，降噪约 %d%%]\n"
                  "Target: %s | 保留 %d 行\n" % (len(olines) - len(folded), len(olines), pct,
                                                 target, len(folded))) + "\n".join(folded)
    else:
        result = "\n".join(olines)

    if limit_tokens and len(result) > limit_tokens:
        result = result[:limit_tokens] + "\n... [截断于 %d 字符，可用 fold/summary 降噪]" % limit_tokens
    return result or "[反编译输出为空]"


def r2_diff(file_a: str, file_b: str, mode: str = "code") -> str:
    """radiff2 二进制差分。"""
    if not os.path.isfile(file_a) or not os.path.isfile(file_b):
        return "[ERROR]: 文件不存在: %s / %s" % (file_a, file_b)
    radiff = _radiff2()
    if not radiff:
        return "[ERROR]: radiff2 不可用"
    flag = {"code": "-C", "hex": "-x", "stats": "-s"}.get((mode or "code").lower(), "-C")
    return _run([radiff, flag, os.path.abspath(file_a), os.path.abspath(file_b)], timeout=120)


def r2_asm(code_or_hex: str, arch: str = "x86", bits: int = 64, disasm: bool = False) -> str:
    """rasm2 汇编 / 反汇编。"""
    rasm = _rasm2()
    if not rasm:
        return "[ERROR]: rasm2 不可用"
    cmd = [rasm, "-a", arch, "-b", str(bits)]
    if disasm:
        cmd.extend(["-d", code_or_hex.strip()])
    else:
        cmd.append(code_or_hex.strip())
    return _run(cmd).strip()


def r2_xrefs(binary_path: str, target: str, direction: str = "to", limit: int = 10) -> str:
    """交叉引用查询（带分页与统计）。"""
    if not os.path.isfile(binary_path):
        return "[ERROR]: 文件不存在: %s" % binary_path
    r2 = _r2_exe()
    if not r2:
        return "[ERROR]: radare2 不可用"
    d = (direction or "to").lower()
    cmd = "aaa; %s @ %s" % ("axt" if d == "to" else "axf", target)
    out = _run([r2, "-q", "-e", "scr.color=0", "-c", cmd,
                os.path.abspath(binary_path)], timeout=120)
    lines = [l for l in out.splitlines()
             if l.strip() and not l.startswith(("INFO:", "WARN:"))]
    total = len(lines)
    shown = lines[:limit]
    head = ["[XREFS %s — %s | 共 %d 条，显示前 %d 条]"
            % (d.upper(), target, total, min(limit, total)),
            "-" * 60]
    body = head + shown
    if total > limit:
        body.append("... [已截断，剩余 %d 条；可增大 limit 或缩小目标]" % (total - limit))
    return "\n".join(body)


# ---------------------------------------------------------------------------
# 3. Android APK
# ---------------------------------------------------------------------------
def apk_info(apk_path: str) -> str:
    """原生解析 APK 结构（免 Java）。"""
    if not os.path.isfile(apk_path):
        return "[ERROR]: APK 不存在: %s" % apk_path
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            names = z.namelist()
            dex = [f for f in names if f.endswith(".dex")]
            so = [f for f in names if f.endswith(".so")]
            meta = [f for f in names if f.startswith("META-INF/")]
            arches = set()
            for s in so:
                parts = s.split("/")
                if len(parts) >= 2 and parts[0] == "lib":
                    arches.add(parts[1])
            manifest_markers: List[str] = []
            if "AndroidManifest.xml" in names:
                raw = z.read("AndroidManifest.xml")
                for item in re.findall(rb"[\x20-\x7e]{4,}", raw):
                    s = item.decode("ascii", errors="ignore")
                    if any(k in s.lower() for k in ("android", "permission", "activity",
                                                    "service", "receiver", "provider", "package")):
                        manifest_markers.append(s)
            return json.dumps({
                "file_size": os.path.getsize(apk_path),
                "dex_count": len(dex),
                "dex_files": dex,
                "native_architectures": sorted(arches),
                "native_libraries_count": len(so),
                "signed_certificates": meta[:5],
                "manifest_key_markers": manifest_markers[:30],
            }, ensure_ascii=False, indent=2)[:40000]
    except Exception as e:
        return "[ERROR]: 解析 APK 失败: %s" % e


def apk_decompile(apk_path: str, output_dir: str = "", deobfuscate: bool = True,
                  timeout: int = 900) -> str:
    """jadx 全量反编译。"""
    if not os.path.isfile(apk_path):
        return "[ERROR]: APK 不存在: %s" % apk_path
    jadx = _jadx()
    if not jadx:
        return "[ERROR]: jadx 不可用"
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(os.path.abspath(apk_path)),
                                  Path(apk_path).stem + "_jadx_src")
    os.makedirs(output_dir, exist_ok=True)
    cmd = [jadx, "-d", output_dir]
    if deobfuscate:
        cmd.append("--deobf")
    cmd.append(os.path.abspath(apk_path))
    out = _run(cmd, timeout=timeout)
    n = sum(len(f) for _, _, f in os.walk(output_dir))
    return "反编译完成\n输出目录: %s\n文件数: %d\n日志: %s" % (output_dir, n, out[:500])


def apk_unpack(apk_path: str, output_dir: str = "", no_src: bool = False,
               timeout: int = 600) -> str:
    """apktool 解包。"""
    if not os.path.isfile(apk_path):
        return "[ERROR]: APK 不存在: %s" % apk_path
    jar = _apktool_jar()
    java = _java()
    if not jar or not java:
        return "[ERROR]: apktool.jar 或 java 不可用"
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(os.path.abspath(apk_path)),
                                  Path(apk_path).stem + "_apktool")
    cmd = [java, "-jar", jar, "d", "-f"]
    if no_src:
        cmd.append("-s")
    cmd.extend(["-o", output_dir, os.path.abspath(apk_path)])
    out = _run(cmd, timeout=timeout)
    n = sum(len(f) for _, _, f in os.walk(output_dir))
    return "解包完成\n输出目录: %s\n文件数: %d\n日志: %s" % (output_dir, n, out[:500])


def apk_smali_search(directory: str, pattern: str, case_sensitive: bool = False,
                     limit: int = 50) -> str:
    """在 smali / 源码中正则搜索。"""
    if not os.path.isdir(directory):
        return "[ERROR]: 目录不存在: %s" % directory
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        return "[ERROR]: 正则无效: %s" % e
    hits = []
    for root, _, files in os.walk(directory):
        for f in files:
            if not f.endswith((".smali", ".java", ".xml", ".json", ".txt")):
                continue
            fp = os.path.join(root, f)
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    for idx, line in enumerate(fh, 1):
                        if rx.search(line):
                            hits.append("%s:%d: %s" % (
                                os.path.relpath(fp, directory), idx, line.strip()[:200]))
                            if len(hits) >= limit:
                                break
            except OSError:
                continue
        if len(hits) >= limit:
            break
    if not hits:
        return "未找到匹配 '%s'" % pattern
    res = hits[:limit]
    if len(hits) >= limit:
        res.append("... [已达到 %d 条上限]" % limit)
    return "\n".join(res)


def apk_gen_hook(framework: str = "frida", class_name: str = "com.example.app.MainActivity",
                 method_name: str = "checkFlag", param_types: Optional[List[str]] = None,
                 return_type: str = "boolean", hook_timing: str = "after") -> str:
    """生成 Frida / BeanShell Hook 脚本。"""
    param_types = param_types or []
    if (framework or "frida").lower() == "frida":
        joined = "', '".join(param_types)
        overload = "'%s'" % joined if param_types else ""
        head = (
            "// Frida Hook: %s.%s\n"
            "// 由 seep-zcode 生成\n"
            "Java.perform(function () {\n"
            "    var target = Java.use(\"%s\");\n"
            "    var method = target[\"%s\"];\n"
            "    if (%s) {\n"
            "        method = method.overload(%s);\n"
            "    }\n"
            "\n"
            "    method.implementation = function () {\n"
            "        console.log(\"[*] Hooked %s.%s\");\n"
            "        for (var i = 0; i < arguments.length; i++) {\n"
            "            console.log(\"    arg[\" + i + \"]: \" + arguments[i]);\n"
            "        }\n"
            % (class_name, method_name, class_name, method_name,
               "true" if param_types else "false", overload,
               class_name, method_name)
        )
        if (hook_timing or "after").lower() == "replace":
            default_ret = "true" if return_type == "boolean" else (
                "null" if return_type == "void" else "0")
            tail = (
                "        console.log(\"[*] 返回值已劫持为: %s\");\n"
                "        return %s;\n"
                "    };\n"
                "});\n" % (default_ret, default_ret)
            )
        else:
            tail = (
                "        var ret = this.%s.apply(this, arguments);\n"
                "        console.log(\"[*] 原返回值: \" + ret);\n"
                "        return ret;\n"
                "    };\n"
                "});\n" % method_name
            )
        return head + tail

    # BeanShell / LSPosed 骨架（不依赖上游模板文件，自带最小可用版）
    pre = ('Class[] paramTypes = new Class[] { %s };\n'
           '    java.lang.reflect.Method targetMethod = ReflectUtils.findMethod('
           'targetClass, "%s", paramTypes);'
           % (", ".join('ReflectUtils.findClass("%s", hostLoader)' % p for p in param_types),
              method_name)) if param_types else (
        'java.lang.reflect.Method targetMethod = ReflectUtils.findMethod('
        'targetClass, "%s", null);' % method_name)
    return (
        "// BeanShell / LSPosed Hook: %s.%s\n"
        "// 时机: %s\n"
        "void hook_%s() {\n"
        "    Class targetClass = ReflectUtils.findClass(\"%s\", hostLoader);\n"
        "    %s\n"
        "    XposedBridge.hookMethod(targetMethod, new XC_MethodHook() {\n"
        "        @Override\n"
        "        protected void %s(MethodHookParam param) throws Throwable {\n"
        "            // TODO: 在这里处理参数 / 返回值\n"
        "        }\n"
        "    });\n"
        "}\n"
        % (class_name, method_name, hook_timing, method_name, class_name, pre,
           "beforeHookedMethod" if (hook_timing or "after").lower() == "before" else "afterHookedMethod")
    )


# ---------------------------------------------------------------------------
# 4. 工作流
# ---------------------------------------------------------------------------
def task_init(task_name: str, description: str = "") -> str:
    """创建规范任务工作区（samples/exports/patches/reports）。"""
    clean = re.sub(r"[^\w\-]", "_", (task_name or "").strip())
    if not clean:
        return "[ERROR]: task_name 不能为空"
    root = os.path.join(_base_dir(), clean)
    subdirs = ["samples", "exports", "patches", "reports"]
    try:
        os.makedirs(root, exist_ok=True)
        created = [clean]
        for s in subdirs:
            os.makedirs(os.path.join(root, s), exist_ok=True)
            created.append("%s/%s" % (clean, s))
        readme = os.path.join(root, "README.md")
        if not os.path.exists(readme):
            with open(readme, "w", encoding="utf-8") as f:
                f.write("# 任务工作区: %s\n\n" % clean)
                f.write("- 任务描述: %s\n\n" % (description or "授权安全检测任务"))
                f.write("## 目录约定\n")
                f.write("- `samples/`: 原始目标与待测样本\n")
                f.write("- `exports/`: 反编译产物、字符串导出、日志\n")
                f.write("- `patches/`: PoC 代码、跳板工程、热补丁\n")
                f.write("- `reports/`: 最终评估报告\n")
        return json.dumps({"status": "Success", "task_directory": root,
                           "created_directories": created,
                           "message": "任务工作区 [%s] 已创建，产物请存于该目录。" % clean},
                          ensure_ascii=False, indent=2)
    except Exception as e:
        return "[ERROR]: 初始化失败: %s" % e


def auto_triage(target_path: str, task_name: str = "") -> str:
    """一键侦察：哈希 + 架构 + 安全机制 + 高价值字符串。"""
    if not os.path.exists(target_path):
        return "[ERROR]: 目标不存在: %s" % target_path
    tp = Path(target_path).resolve()
    size = os.path.getsize(tp)

    h = hashlib.sha256()
    md5 = hashlib.md5()
    with open(tp, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            md5.update(chunk)

    info: Dict[str, Any] = {}
    rabin2 = _rabin2()
    if rabin2:
        raw = _run([rabin2, "-Ij", str(tp)], raw=True)
        try:
            info = json.loads(raw).get("info", {}) or {}
        except Exception:
            info = {}

    kws = ["vip", "license", "auth", "expire", "token", "subscri",
           "register", "check", "trial", "valid"]
    matched: List[Dict[str, str]] = []
    if rabin2:
        # -zz 全段 + -j JSON，才能拿到 {"strings":[{vaddr,string}]}
        raw = _run([rabin2, "-zz", "-j", str(tp)], timeout=180, raw=True)
        try:
            for s in json.loads(raw).get("strings", []) or []:
                v = s.get("string", "")
                if any(k in v.lower() for k in kws):
                    matched.append({"vaddr": hex(s.get("vaddr", 0)), "string": v[:80]})
                if len(matched) >= 20:
                    break
        except Exception:
            pass

    result: Dict[str, Any] = {
        "file_name": tp.name,
        "file_size": "%.2f MB" % (size / 1048576),
        "hashes": {"md5": md5.hexdigest(), "sha256": h.hexdigest()},
        "binary_profile": {
            "arch": info.get("arch", "unknown"),
            "bits": info.get("bits", "unknown"),
            "format": info.get("bintype", "unknown"),
            "canary": info.get("canary", False),
            "nx": info.get("nx", False),
            "pic": info.get("pic", False),
            "stripped": info.get("stripped", False),
            "compiler": info.get("compiler", "unknown"),
        },
        "auth_related_strings_sampled": matched[:15],
        "recommended_action": (
            "下一步：1) 若已开 IDA，用 ida MCP 定位决策分支；"
            "2) 若为本地判定，用 seep_apk_gen_hook 或热补丁验证；"
            "3) 报告与验证代码归档到 reports/ 与 patches/。"
        ),
    }

    if task_name:
        clean = re.sub(r"[^\w\-]", "_", task_name.strip())
        rdir = os.path.join(_base_dir(), clean, "reports")
        if os.path.isdir(rdir):
            out_file = os.path.join(rdir, "%s_triage.json" % tp.stem)
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            result["saved_report"] = out_file

    return json.dumps(result, ensure_ascii=False, indent=2)


def ida_status() -> str:
    """探测本机 IDA MCP 服务（13337）。"""
    for port in (13337, 13338):
        try:
            req = urllib.request.Request("http://127.0.0.1:%d" % port, method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                return json.dumps({"status": "Online", "port": port, "code": resp.status,
                                   "message": "IDA MCP 在线，可直接用 ida 系列工具。"},
                                  ensure_ascii=False, indent=2)
        except Exception as e:
            last = str(e)
    return json.dumps({
        "status": "Offline",
        "detail": last[:200] if "last" in dir() else "连接失败",
        "hint": "确认 IDA Pro 已打开插件，或改用 ida_vm（虚拟机内 IDA，端口 3101）。",
    }, ensure_ascii=False, indent=2)


def gen_security_report(task_name: str, target_name: str,
                        vuln_type: str = "CWE-602: 客户端鉴权与状态判定缺陷",
                        branch_location: str = "0x0", description: str = "",
                        poc_summary: str = "", defense_recommendation: str = "") -> str:
    """生成安全评估报告到 reports/。"""
    clean = re.sub(r"[^\w\-]", "_", (task_name or "").strip())
    if not clean:
        return "[ERROR]: task_name 不能为空"
    rdir = os.path.join(_base_dir(), clean, "reports")
    try:
        os.makedirs(rdir, exist_ok=True)
    except Exception as e:
        return "[ERROR]: 无法创建报告目录: %s" % e

    report = os.path.join(rdir, "%s_security_assessment_report.md" % target_name)
    rem = defense_recommendation or (
        "1. **服务端统一鉴权**：核心特权逻辑迁至云端，客户端仅作渲染，"
        "受限资源由服务端签发带时间戳与签名的 Token。\n"
        "2. **非对称验签**：离线场景用 RSA/ECC，客户端只持公钥，私钥留服务端。\n"
        "3. **内存完整性**：启用 `ProcessDynamicCodePolicy` 抑制动态内存执行，"
        "敏感模块加代码段自校验。"
    )
    body = (
        "# 软件安全评估与鉴权脆弱性走查报告\n\n"
        "- **目标资产**: `%s`\n"
        "- **评估类型**: 白盒代码走查 / 客户端决策逻辑安全性验证\n"
        "- **缺陷分类**: `%s`\n"
        "- **报告归属**: `%s/reports/`\n\n---\n\n"
        "## 1. 风险概述\n%s\n\n---\n\n"
        "## 2. 关键判定位点\n- **函数 / 偏移**: `%s`\n"
        "```text\n; 典型本地鉴权分支\nTEST EAX, EAX\nJZ   loc_restricted_feature\n```\n\n---\n\n"
        "## 3. 验证 PoC\n%s\n\n---\n\n"
        "## 4. 加固建议\n%s\n"
        % (target_name, vuln_type, clean,
           description or "客户端采用本地离线决策，缺少服务端强鉴权与非对称验签，"
                          "完全依据本地状态位放行，构成 CWE-602 本地判定信任缺陷。",
           branch_location,
           poc_summary or "通过动态 Hook / 内存标志位修正，验证在不经服务端鉴权的前提下本地逻辑可直接放行。",
           rem)
    )
    try:
        with open(report, "w", encoding="utf-8") as f:
            f.write(body)
    except OSError as e:
        return "[ERROR]: 写报告失败: %s" % e
    return "报告已生成: %s（%d 字符）" % (report, len(body))
