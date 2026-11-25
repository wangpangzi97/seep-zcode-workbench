#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VM 内工具专用封装（结构化输出层）

为什么需要这一层
    通用 `seep_vm_run` 只能把 stdout 原样丢回来。但每个工具的坑都不一样：
      - die.exe 是 GUI 版，无参数会卡死；必须用 diec.exe
      - sigcheck 通过管道捕获时输出 UTF-16LE，不是 UTF-8
      - pe-sieve 的 /json 打到 stdout，且要 /quiet
      - upx -l 对未加壳文件返回 exit code 2（语义不是错误）
      - capa 的 analysis 在 meta 里，ATT&CK 在 rules[*].meta.attack
      - pefile 必须不用 fast_load，否则导入表为空
    这一层把每个工具的参数、编码、退出码语义、输出解析固化下来，
    对外只返回结构化 dict，不让调用方猜。

实现约定（重要）
    guest 侧代码统一用字符串拼接生成，**禁止用 % 格式化** ——
    因为 JSON 字面量里含 `%`，与 `%d` 混用会抛 TypeError。
    超时值统一通过 _T(sec) 生成片段。
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

TOOLS = {
    "capa": r"C:\ProgramData\chocolatey\bin\capa.exe",
    "floss": r"C:\Tools\FLOSS\floss.exe",
    "diec": r"C:\Tools\die\diec.exe",
    "die": r"C:\Tools\die\die.exe",
    "pe_sieve": r"C:\ProgramData\chocolatey\bin\pe-sieve.exe",
    "hollows_hunter": r"C:\ProgramData\chocolatey\bin\hollows_hunter.exe",
    "strings": r"C:\Tools\sysinternals\strings.exe",
    "strings64": r"C:\Tools\sysinternals\strings64.exe",
    "sigcheck": r"C:\Tools\sysinternals\sigcheck.exe",
    "upx": r"C:\ProgramData\chocolatey\bin\upx.exe",
    "7z": r"C:\ProgramData\chocolatey\bin\7z.exe",
    "yara": r"C:\ProgramData\chocolatey\bin\yara.exe",
    "nmap": r"C:\Program Files (x86)\Nmap\nmap.exe",
    "tshark": r"C:\ProgramData\chocolatey\bin\tshark.exe",
    "dnspy": r"C:\ProgramData\chocolatey\bin\dnSpy.Console.exe",
    "de4dot": r"C:\ProgramData\chocolatey\bin\de4dot.exe",
    "apktool": r"C:\Tools\apktool\apktool.bat",
    "frida": r"C:\Python313\Scripts\frida.exe",
    "ida": r"C:\Program Files\IDA Professional 9.5\idat.exe",
}
PY = r"C:\Python313\python.exe"
WORKDIR = r"C:\zcode-mcp"


# ---------------------------------------------------------------------------
# 代码生成辅助（杜绝 % 格式化）
# ---------------------------------------------------------------------------
def _hdr() -> str:
    """guest 侧公共前置代码。"""
    return (
        "import subprocess, json, os, sys, glob\n"
        "TOOLS = " + repr(TOOLS) + "\n"
        "def run(cmd, timeout=120, enc=None, text=True):\n"
        "    try:\n"
        "        kw = dict(capture_output=True, timeout=timeout)\n"
        "        if enc:\n"
        "            kw['encoding'] = enc\n"
        "            kw['errors'] = 'replace'\n"
        "        p = subprocess.run(cmd, **kw)\n"
        "        o = p.stdout\n"
        "        e = p.stderr\n"
        "        if isinstance(o, bytes):\n"
        "            o = o.decode('utf-8', 'replace')\n"
        "        if isinstance(e, bytes):\n"
        "            e = e.decode('utf-8', 'replace')\n"
        "        return p.returncode, (o or ''), (e or '')\n"
        "    except subprocess.TimeoutExpired:\n"
        "        return -9, '', 'TIMEOUT'\n"
        "    except Exception as ex:\n"
        "        return -1, '', str(ex)\n"
        "def emit(obj):\n"
        "    sys.stdout.write(json.dumps(obj, ensure_ascii=False))\n"
    )


def _s(v: Any) -> str:
    """把值转成可以嵌进生成的 python 源码的字符串字面量。"""
    return repr(v)


def _inner(timeout: int, reserve: int = 60) -> str:
    return "timeout=" + str(max(30, timeout - reserve))


def _guest_call(runner, code: str, timeout: int = 300) -> Dict[str, Any]:
    """跑 guest python，解析其为 JSON。"""
    try:
        ok, out = runner.run_py(code, timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": "执行失败: " + str(e), "raw": ""}
    out = (out or "").strip()
    if not out:
        return {"ok": False, "error": "无输出（超时或 guest 异常）", "raw": ""}
    try:
        return {"ok": True, "data": json.loads(out), "raw": out}
    except json.JSONDecodeError:
        pass
    m = re.search(r"(\{.*\})\s*$", out, re.S)
    if m:
        try:
            return {"ok": True, "data": json.loads(m.group(1)), "raw": out}
        except json.JSONDecodeError:
            pass
    return {"ok": False, "error": "输出非 JSON", "raw": out[:4000]}


# ---------------------------------------------------------------------------
# 1. capa
# ---------------------------------------------------------------------------
def capa_analyze(runner, target: str, timeout: int = 420) -> Dict[str, Any]:
    """capa 静态能力分析（ATT&CK / MBC / 规则命中）。"""
    code = _hdr() + (
        "\ntarget = " + _s(target) + "\n"
        "rc, out, err = run([TOOLS['capa'], '-j', target], " + _inner(timeout) + ")\n"
        "if not out.strip():\n"
        "    emit({'error': 'capa 无输出', 'rc': rc, 'stderr': err[:500]})\n"
        "else:\n"
        "    emit(json.loads(out))\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "capa", "error": res.get("error"),
                "raw": res.get("raw", "")[:1500]}
    d = res["data"]
    if "error" in d and "rules" not in d:
        return {"ok": False, "tool": "capa", **{k: d[k] for k in d if k != "rules"}}

    meta = d.get("meta") or {}
    sample = meta.get("sample") or {}
    analysis = meta.get("analysis") or {}
    rules = d.get("rules") or {}

    hits: List[Dict[str, Any]] = []
    tactics, techniques, attack_ids, mbc_behaviors = set(), [], set(), set()

    for name, body in rules.items():
        if not isinstance(body, dict):
            continue
        rm = body.get("meta") or {}
        hit: Dict[str, Any] = {
            "rule": name,
            "namespace": rm.get("namespace", ""),
        }
        atk = rm.get("attack") or rm.get("att&ck") or []
        atk_list = []
        if isinstance(atk, list):
            for a in atk:
                if isinstance(a, dict):
                    tac = a.get("tactic", "")
                    tech = a.get("technique", "")
                    sub = a.get("subtechnique", "")
                    tid = a.get("id", "")
                    if tac:
                        tactics.add(tac)
                    label = tech + ("::" + sub if sub else "")
                    if label or tid:
                        techniques.append(label or tid)
                    if tid:
                        attack_ids.add(tid)
                    atk_list.append({"tactic": tac, "technique": label, "id": tid})
                elif isinstance(a, str):
                    atk_list.append({"raw": a})
                    if "::" in a:
                        tac, tech = a.split("::", 1)
                        tactics.add(tac)
                        techniques.append(tech)
        if atk_list:
            hit["att&ck"] = atk_list

        mbc = rm.get("mbc") or []
        mbc_list = []
        if isinstance(mbc, list):
            for m in mbc:
                if isinstance(m, dict):
                    beh = m.get("behavior", "")
                    if beh:
                        mbc_behaviors.add(beh)
                    mbc_list.append({"objective": m.get("objective", ""),
                                     "behavior": beh, "id": m.get("id", "")})
        if mbc_list:
            hit["mbc"] = mbc_list
        hits.append(hit)

    # 有 ATT&CK 情报的排前面
    hits.sort(key=lambda h: (0 if h.get("att&ck") else 1, 0 if h.get("mbc") else 1))

    return {
        "ok": True,
        "tool": "capa",
        "target": target,
        "capa_version": meta.get("version", ""),
        "md5": sample.get("md5", ""),
        "sha1": sample.get("sha1", ""),
        "sha256": sample.get("sha256", ""),
        "format": analysis.get("format", ""),
        "arch": analysis.get("arch", ""),
        "os": analysis.get("os", ""),
        "rule_count": len(hits),
        "tactics": sorted(tactics),
        "techniques": sorted(set(techniques)),
        "attack_ids": sorted(attack_ids),
        "mbc_behaviors": sorted(mbc_behaviors),
        "rules": hits[:60],
    }


# ---------------------------------------------------------------------------
# 2. FLOSS
# ---------------------------------------------------------------------------
def floss_extract(runner, target: str, min_length: int = 6,
                  limit: int = 200, timeout: int = 420) -> Dict[str, Any]:
    """FLOSS 提取静态/解码/栈字符串。"""
    code = _hdr() + (
        "\ntarget = " + _s(target) + "\n"
        "rc, out, err = run([TOOLS['floss'], '-j', '-n', " + str(int(min_length)) +
        ", target], " + _inner(timeout) + ")\n"
        "if not out.strip():\n"
        "    emit({'error': 'FLOSS 无输出', 'rc': rc, 'stderr': err[:500]})\n"
        "else:\n"
        "    emit(json.loads(out))\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "floss", "error": res.get("error"),
                "raw": res.get("raw", "")[:1500]}
    d = res["data"]
    if "error" in d and "strings" not in d:
        return {"ok": False, "tool": "floss", **{k: d[k] for k in d if k != "strings"}}

    strings = d.get("strings") or {}
    static = strings.get("static_strings") or []
    decoded = strings.get("decoded_strings") or []
    stack = strings.get("stack_strings") or []
    tight = strings.get("tight_strings") or []

    def fmt(items, cap):
        out = []
        for it in items[:cap]:
            if isinstance(it, dict):
                s = it.get("string", "")
                if s:
                    out.append(s)
            elif isinstance(it, str):
                out.append(it)
        return out

    meta = d.get("metadata") or {}
    analysis = d.get("analysis") or {}
    fn = analysis.get("functions") or {}
    return {
        "ok": True,
        "tool": "floss",
        "target": target,
        "imagebase": meta.get("imagebase"),
        "counts": {
            "static": len(static),
            "decoded": len(decoded),
            "stack": len(stack),
            "tight": len(tight),
            "decoding_functions": fn.get("discovered", 0),
        },
        "decoded_strings": fmt(decoded, limit),
        "stack_strings": fmt(stack, limit),
        "tight_strings": fmt(tight, max(20, limit // 4)),
    }


# ---------------------------------------------------------------------------
# 3. die（必须 diec.exe）
# ---------------------------------------------------------------------------
def die_detect(runner, target: str, deep: bool = False,
               heuristic: bool = False, timeout: int = 180) -> Dict[str, Any]:
    """Detect It Easy 命令行版（die.exe 是 GUI 会卡死）。"""
    flags = ["-j"]
    if deep:
        flags.append("-r")
    if heuristic:
        flags.append("-u")
    code = _hdr() + (
        "\ntarget = " + _s(target) + "\n"
        "cmd = [TOOLS['diec']] + " + _s(flags) + " + [target]\n"
        "rc, out, err = run(cmd, " + _inner(timeout, 30) + ")\n"
        "i = out.find('{')\n"
        "if i < 0:\n"
        "    emit({'error': 'diec 无 JSON', 'rc': rc, 'out': out[:600]})\n"
        "else:\n"
        "    emit(json.loads(out[i:]))\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "diec", "error": res.get("error"),
                "raw": res.get("raw", "")[:1200]}
    d = res["data"]
    if "error" in d and "detects" not in d:
        return {"ok": False, "tool": "diec", **{k: d[k] for k in d if k != "detects"}}

    summary = {"filetype": "", "linker": "", "compiler": "", "tool": "",
               "packer": "", "protector": "", "lang": ""}
    values = []
    for det in (d.get("detects") or []):
        if not summary["filetype"] and det.get("filetype"):
            summary["filetype"] = det["filetype"]
        for v in (det.get("values") or []):
            t = (v.get("type") or "").lower()
            nm = v.get("name") or ""
            ver = v.get("version") or ""
            values.append({"type": v.get("type", ""), "name": nm,
                           "version": ver, "string": v.get("string", "")})
            joined = (nm + " " + ver).strip()
            if "linker" in t and not summary["linker"]:
                summary["linker"] = joined
            elif "compiler" in t and not summary["compiler"]:
                summary["compiler"] = joined
            elif t in ("tool", "installer") and not summary["tool"]:
                summary["tool"] = joined
            elif "packer" in t and not summary["packer"]:
                summary["packer"] = joined
            elif "protector" in t and not summary["protector"]:
                summary["protector"] = joined
            elif "language" in t and not summary["lang"]:
                summary["lang"] = nm

    return {
        "ok": True, "tool": "diec", "target": target,
        "filetype": summary["filetype"],
        "linker": summary["linker"],
        "compiler": summary["compiler"],
        "build_tool": summary["tool"],       # 避免与 "tool"（工具名）冲突
        "packer": summary["packer"],
        "protector": summary["protector"],
        "language": summary["lang"],
        "all_values": values[:40],
    }


# ---------------------------------------------------------------------------
# 4. sigcheck（UTF-16LE）
# ---------------------------------------------------------------------------
def sigcheck_verify(runner, target: str, timeout: int = 120) -> Dict[str, Any]:
    """sigcheck 数字签名校验。

    坑：管道捕获时输出 UTF-16LE，必须用 bytes 读取后自行解码。
    """
    code = _hdr() + (
        "\ntarget = " + _s(target) + "\n"
        "rc = -1\n"
        "text = ''\n"
        "try:\n"
        "    p = subprocess.run([TOOLS['sigcheck'], '-c', '-q', '-h', target],\n"
        "                       capture_output=True, " + _inner(timeout, 30) + ")\n"
        "    raw = p.stdout or b''\n"
        "    rc = p.returncode\n"
        "    if len(raw) >= 4 and raw[1] == 0 and raw[3] == 0:\n"
        "        text = raw.decode('utf-16-le', 'replace')\n"
        "    else:\n"
        "        text = raw.decode('utf-8', 'replace')\n"
        "    text = text.replace('\\x00', '')\n"
        "except Exception as ex:\n"
        "    text = 'ERR:' + str(ex)[:200]\n"
        "rows = []\n"
        "lines = [l for l in text.splitlines() if l.strip()]\n"
        "hi = -1\n"
        "for i, l in enumerate(lines):\n"
        "    if l.startswith('Path,') or l.startswith('\"Path\"'):\n"
        "        hi = i\n"
        "        break\n"
        "if hi >= 0 and hi + 1 < len(lines):\n"
        "    hdr = lines[hi].split(',')\n"
        "    for ln in lines[hi+1:]:\n"
        "        parts, cur, q = [], '', False\n"
        "        for ch in ln:\n"
        "            if ch == '\"':\n"
        "                q = not q\n"
        "            elif ch == ',' and not q:\n"
        "                parts.append(cur); cur = ''\n"
        "            else:\n"
        "                cur += ch\n"
        "        parts.append(cur)\n"
        "        if len(parts) >= len(hdr):\n"
        "            rows.append(dict(zip(hdr, parts)))\n"
        "emit({'rc': rc, 'rows': rows, 'head': text[:300]})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "sigcheck", "error": res.get("error"),
                "raw": res.get("raw", "")[:1200]}
    d = res["data"]
    rows = d.get("rows") or []
    if not rows:
        return {"ok": False, "tool": "sigcheck", "error": "未解析出 CSV 行",
                "raw": (d.get("head") or "")[:600]}
    r = rows[0]
    return {
        "ok": True, "tool": "sigcheck",
        "path": r.get("Path", ""),
        "verified": r.get("Verified", ""),
        "signing_date": r.get("Date", ""),
        "publisher": r.get("Publisher", ""),
        "company": r.get("Company", ""),
        "description": r.get("Description", ""),
        "product": r.get("Product", ""),
        "product_version": r.get("Product Version", ""),
        "file_version": r.get("File Version", ""),
        "machine_type": r.get("Machine Type", ""),
        "md5": r.get("MD5", ""),
        "sha1": r.get("SHA1", ""),
        "sha256": r.get("SHA256", ""),
        "imps": r.get("IMP", ""),
    }


# ---------------------------------------------------------------------------
# 5. strings
# ---------------------------------------------------------------------------
def strings_extract(runner, target: str, min_length: int = 8,
                    unicode_only: bool = False, limit: int = 400,
                    timeout: int = 180) -> Dict[str, Any]:
    """Sysinternals strings 提取。"""
    args = ["-n", str(int(min_length))]
    if unicode_only:
        args.append("-u")
    args.append(target)
    code = _hdr() + (
        "\nrc, out, err = run([TOOLS['strings']] + " + _s(args) + ", " + _inner(timeout, 30) + ")\n"
        "lines = [l for l in (out or '').splitlines() if l.strip()]\n"
        "body = [l for l in lines if 'Sysinternals' not in l\n"
        "        and not l.startswith('Copyright') and not l.startswith('Strings v')]\n"
        "emit({'rc': rc, 'total': len(body), 'items': body[:" + str(int(limit)) + "]})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "strings", "error": res.get("error"),
                "raw": res.get("raw", "")[:1200]}
    d = res["data"]
    return {"ok": True, "tool": "strings", "target": target,
            "min_length": min_length, "unicode_only": unicode_only,
            "total": d.get("total", 0), "items": d.get("items", [])}


# ---------------------------------------------------------------------------
# 6. upx
# ---------------------------------------------------------------------------
def upx_probe(runner, target: str, timeout: int = 120) -> Dict[str, Any]:
    """检测 UPX 加壳（upx -l 未加壳时 exit code 2，不是错误）。"""
    code = _hdr() + (
        "\nrc, out, err = run([TOOLS['upx'], '-l', " + _s(target) + "], " +
        _inner(timeout, 30) + ")\n"
        "combined = (out or '') + (err or '')\n"
        "packed = ('NotPacked' not in combined) and ('not packed' not in combined.lower())\n"
        "emit({'rc': rc, 'packed': packed, 'out': combined[:800]})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "upx", "error": res.get("error"),
                "raw": res.get("raw", "")[:1000]}
    d = res["data"]
    return {"ok": True, "tool": "upx", "target": target,
            "packed": bool(d.get("packed")), "exit_code": d.get("rc"),
            "detail": (d.get("out") or "")[-400:]}


def upx_unpack(runner, target: str, out_dir: str = r"C:\zcode-mcp\unpacked",
               timeout: int = 180) -> Dict[str, Any]:
    """UPX 脱壳。"""
    code = _hdr() + (
        "\nimport os\n"
        "target = " + _s(target) + "\n"
        "outd = " + _s(out_dir) + "\n"
        "os.makedirs(outd, exist_ok=True)\n"
        "dst = os.path.join(outd, os.path.basename(target))\n"
        "rc, out, err = run([TOOLS['upx'], '-d', '-o', dst, target], " +
        _inner(timeout, 30) + ")\n"
        "emit({'rc': rc, 'out': ((out or '')+(err or ''))[:800],\n"
        "      'dir': outd, 'files': os.listdir(outd)})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "upx", "error": res.get("error"),
                "raw": res.get("raw", "")[:1000]}
    d = res["data"]
    return {"ok": d.get("rc") == 0, "tool": "upx-unpack", "target": target,
            "out_dir": d.get("dir"), "files": d.get("files", []),
            "detail": d.get("out", "")}


# ---------------------------------------------------------------------------
# 7. pe-sieve / hollows_hunter
# ---------------------------------------------------------------------------
def pesieve_scan(runner, pid: int, timeout: int = 180,
                 dump_dir: str = r"C:\zcode-mcp\sieve") -> Dict[str, Any]:
    """扫描指定进程内存，识别注入/替换/hook。"""
    code = _hdr() + (
        "\nimport os\n"
        "pid = " + str(int(pid)) + "\n"
        "dumpd = " + _s(dump_dir) + "\n"
        "os.makedirs(dumpd, exist_ok=True)\n"
        "args = [TOOLS['pe_sieve'], '/pid', str(pid), '/quiet', '/json', '/dir', dumpd]\n"
        "rc, out, err = run(args, " + _inner(timeout, 30) + ")\n"
        "emit({'rc': rc, 'out': (out or '')[:6000], 'err': (err or '')[:600],\n"
        "      'dump_dir': dumpd})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "pe-sieve", "error": res.get("error"),
                "raw": res.get("raw", "")[:1500]}
    d = res["data"]
    raw = d.get("out") or ""
    parsed = None
    i = raw.find("{")
    if i >= 0:
        try:
            parsed = json.loads(raw[i:])
        except json.JSONDecodeError:
            parsed = None

    # pe-sieve 的 JSON 外层是 scan_report，不是 summary
    report = (parsed or {}).get("scan_report") or parsed or {}
    out = {
        "ok": True,
        "tool": "pe-sieve",
        "pid": pid,
        # 注意：rc=1 是正常语义（扫描完成但无可疑项），rc=0 才少见
        "exit_code": d.get("rc"),
        "note_rc": "pe-sieve 返回 1 表示扫描完成、未发现可疑项，属正常",
        "dump_dir": d.get("dump_dir"),
    }
    if report:
        scanned = report.get("scanned") or {}
        modified = scanned.get("modified") or {}
        suspects = report.get("suspects") or report.get("suspicious") or {}
        out["main_image"] = report.get("main_image_path", "")
        out["is_64_bit"] = report.get("is_64_bit")
        out["is_managed"] = report.get("is_managed")
        out["scanner_version"] = report.get("scanner_version", "")
        out["scanned"] = scanned
        out["modified"] = modified
        out["suspicious"] = suspects
        out["suspicious_total"] = (
            suspects.get("total") if isinstance(suspects, dict)
            else len(suspects) if isinstance(suspects, list) else 0
        )
        out["modules"] = (report.get("scanned_modules") or [])[:20]
    else:
        out["raw_summary"] = raw[-2000:]
        out["note"] = "JSON 解析失败，返回原始摘要。"
    return out


def pesieve_hunt(runner, timeout: int = 240,
                 dump_dir: str = r"C:\zcode-mcp\hunt") -> Dict[str, Any]:
    """hollows_hunter 全系统扫描。"""
    code = _hdr() + (
        "\nimport os\n"
        "dumpd = " + _s(dump_dir) + "\n"
        "os.makedirs(dumpd, exist_ok=True)\n"
        "rc, out, err = run([TOOLS['hollows_hunter'], '/quiet', '/json', '/dir', dumpd], " +
        _inner(timeout, 60) + ")\n"
        "emit({'rc': rc, 'out': (out or '')[:6000], 'dump_dir': dumpd})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "hollows_hunter", "error": res.get("error"),
                "raw": res.get("raw", "")[:1500]}
    d = res["data"]
    raw = d.get("out") or ""
    i = raw.find("{")
    if i >= 0:
        try:
            parsed = json.loads(raw[i:])
            report = parsed.get("scan_report") or parsed
            scanned = report.get("scanned") or {}
            suspects = report.get("suspects") or {}
            return {"ok": True, "tool": "hollows_hunter",
                    "exit_code": d.get("rc"),
                    "scanned": scanned,
                    "suspicious": suspects,
                    "suspicious_total": (suspects.get("total") if isinstance(suspects, dict) else 0),
                    "dump_dir": d.get("dump_dir")}
        except json.JSONDecodeError:
            pass
    return {"ok": False, "tool": "hollows_hunter", "error": "解析失败",
            "raw": raw[-2000:]}


# ---------------------------------------------------------------------------
# 8. yara
# ---------------------------------------------------------------------------
def yara_scan(runner, target: str, rule: str = "", rule_file: str = "",
              timeout: int = 180) -> Dict[str, Any]:
    """YARA 规则扫描。"""
    code = _hdr() + (
        "\nimport uuid\n"
        "target = " + _s(target) + "\n"
        "rule_txt = " + _s(rule) + "\n"
        "rule_file = " + _s(rule_file) + "\n"
        "if rule_txt and not rule_file:\n"
        "    rule_file = r'C:\\zcode-mcp\\__yara_' + uuid.uuid4().hex[:8] + '.yar'\n"
        "    open(rule_file, 'w', encoding='utf-8').write(rule_txt)\n"
        "rc, out, err = run([TOOLS['yara'], '-s', rule_file, target], " +
        _inner(timeout, 30) + ")\n"
        "emit({'rc': rc, 'out': (out or '')[:5000], 'err': (err or '')[:500],\n"
        "      'rule_file': rule_file})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "yara", "error": res.get("error"),
                "raw": res.get("raw", "")[:1200]}
    d = res["data"]
    out = d.get("out") or ""
    matches = [l for l in out.splitlines() if l.strip() and not l.startswith("0x")]
    return {"ok": d.get("rc") == 0, "tool": "yara", "target": target,
            "rule_file": d.get("rule_file"), "matched": len(matches),
            "matches": matches[:100], "detail": out[:3000]}


# ---------------------------------------------------------------------------
# 9. 7z
# ---------------------------------------------------------------------------
def sevenzip_list(runner, archive: str, timeout: int = 120) -> Dict[str, Any]:
    code = _hdr() + (
        "\nrc, out, err = run([TOOLS['7z'], 'l', " + _s(archive) + "], " +
        _inner(timeout, 30) + ")\n"
        "emit({'rc': rc, 'out': ((out or '')+(err or ''))[:6000]})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "7z", "error": res.get("error"),
                "raw": res.get("raw", "")[:1200]}
    d = res["data"]
    return {"ok": d.get("rc") == 0, "tool": "7z-list", "archive": archive,
            "listing": d.get("out", "")[:5000]}


def sevenzip_extract(runner, archive: str, out_dir: str,
                     password: str = "", timeout: int = 300) -> Dict[str, Any]:
    extra = ["-p" + password] if password else []
    code = _hdr() + (
        "\nimport os\n"
        "outd = " + _s(out_dir) + "\n"
        "os.makedirs(outd, exist_ok=True)\n"
        "args = [TOOLS['7z'], 'x', " + _s(archive) + ", '-o' + outd, '-y'] + " +
        _s(extra) + "\n"
        "rc, out, err = run(args, " + _inner(timeout, 60) + ")\n"
        "n = sum(len(f) for _, _, f in os.walk(outd))\n"
        "emit({'rc': rc, 'files': n, 'out_dir': outd,\n"
        "      'detail': ((out or '')+(err or ''))[:1000]})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "7z", "error": res.get("error"),
                "raw": res.get("raw", "")[:1200]}
    d = res["data"]
    return {"ok": d.get("rc") == 0, "tool": "7z-extract", "archive": archive,
            "out_dir": d.get("out_dir"), "file_count": d.get("files", 0),
            "detail": d.get("detail", "")}


# ---------------------------------------------------------------------------
# 10. .NET
# ---------------------------------------------------------------------------
def dnspy_decompile(runner, target: str, out_dir: str = r"C:\zcode-mcp\dnspy",
                    timeout: int = 600) -> Dict[str, Any]:
    code = _hdr() + (
        "\nimport os\n"
        "target = " + _s(target) + "\n"
        "outd = " + _s(out_dir) + "\n"
        "os.makedirs(outd, exist_ok=True)\n"
        "rc, out, err = run([TOOLS['dnspy'], '-o', outd, target], " +
        _inner(timeout, 60) + ")\n"
        "n = sum(len(f) for _, _, f in os.walk(outd))\n"
        "cs = [f for _, _, fs in os.walk(outd) for f in fs if f.endswith('.cs')]\n"
        "emit({'rc': rc, 'file_count': n, 'cs_count': len(cs), 'out_dir': outd,\n"
        "      'cs_sample': cs[:20], 'detail': ((out or '')+(err or ''))[:800]})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "dnSpy", "error": res.get("error"),
                "raw": res.get("raw", "")[:1200]}
    d = res["data"]
    return {"ok": d.get("file_count", 0) > 0, "tool": "dnSpy", "target": target,
            "out_dir": d.get("out_dir"), "file_count": d.get("file_count", 0),
            "cs_count": d.get("cs_count", 0), "cs_sample": d.get("cs_sample", []),
            "detail": d.get("detail", "")}


def de4dot_clean(runner, target: str, out_dir: str = r"C:\zcode-mcp\de4dot",
                 timeout: int = 300) -> Dict[str, Any]:
    code = _hdr() + (
        "\nimport os\n"
        "target = " + _s(target) + "\n"
        "outd = " + _s(out_dir) + "\n"
        "os.makedirs(outd, exist_ok=True)\n"
        "rc, out, err = run([TOOLS['de4dot'], '-o', outd, target], " +
        _inner(timeout, 60) + ")\n"
        "emit({'rc': rc, 'files': os.listdir(outd),\n"
        "      'detail': ((out or '')+(err or ''))[:800]})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "de4dot", "error": res.get("error"),
                "raw": res.get("raw", "")[:1200]}
    d = res["data"]
    return {"ok": d.get("rc") == 0, "tool": "de4dot", "target": target,
            "out_dir": out_dir, "files": d.get("files", []),
            "detail": d.get("detail", "")}


# ---------------------------------------------------------------------------
# 11. APK
# ---------------------------------------------------------------------------
def apk_decode(runner, apk: str, out_dir: str = r"C:\zcode-mcp\apk",
               no_src: bool = False, timeout: int = 600) -> Dict[str, Any]:
    flags = ["-f"]
    if no_src:
        flags.append("-s")
    code = _hdr() + (
        "\nimport os\n"
        "apk = " + _s(apk) + "\n"
        "outd = " + _s(out_dir) + "\n"
        "rc, out, err = run([TOOLS['apktool'], 'd', apk, '-o', outd] + " +
        _s(flags) + ", " + _inner(timeout, 60) + ")\n"
        "files = sum(len(f) for _, _, f in os.walk(outd)) if os.path.isdir(outd) else 0\n"
        "smali = sum(1 for _, ds, _ in os.walk(outd) for x in ds if x.startswith('smali'))\n"
        "emit({'rc': rc, 'files': files, 'smali_dirs': smali, 'out_dir': outd,\n"
        "      'detail': ((out or '')+(err or ''))[:1000]})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "apktool", "error": res.get("error"),
                "raw": res.get("raw", "")[:1500]}
    d = res["data"]
    return {"ok": d.get("rc") == 0, "tool": "apktool", "apk": apk,
            "out_dir": d.get("out_dir"), "file_count": d.get("files", 0),
            "smali_dirs": d.get("smali_dirs", 0), "detail": d.get("detail", "")}


# ---------------------------------------------------------------------------
# 12. 网络
# ---------------------------------------------------------------------------
def nmap_scan(runner, target: str, ports: str = "", top_ports: int = 0,
              service_detect: bool = True, timeout: int = 300) -> Dict[str, Any]:
    args = ["-Pn", "-T4"]
    if service_detect:
        args.append("-sV")
    if ports:
        args.extend(["-p", ports])
    elif top_ports:
        args.extend(["--top-ports", str(int(top_ports))])
    args.append(target)

    code = _hdr() + (
        "\nargs = [TOOLS['nmap']] + " + _s(args) + "\n"
        "rc, out, err = run(args, " + _inner(timeout, 60) + ")\n"
        "combined = (out or '') + (err or '')\n"
        "found = []\n"
        "import re as _re\n"
        "for line in combined.splitlines():\n"
        "    m = _re.match(r'^(\\d+)/(tcp|udp)\\s+(open|filtered|closed)\\s+(\\S+)\\s*(.*)$', line.strip())\n"
        "    if m:\n"
        "        found.append({'port': int(m.group(1)), 'proto': m.group(2),\n"
        "                      'state': m.group(3), 'service': m.group(4),\n"
        "                      'version': m.group(5)})\n"
        "emit({'rc': rc, 'ports': found, 'args': args, 'raw': combined[:3000]})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "nmap", "error": res.get("error"),
                "raw": res.get("raw", "")[:1500]}
    d = res["data"]
    ports_found = d.get("ports") or []
    return {"ok": d.get("rc") == 0, "tool": "nmap", "target": target,
            "open_count": len([p for p in ports_found if p.get("state") == "open"]),
            "ports": ports_found, "args": d.get("args", []),
            "raw": (d.get("raw") or "")[:2500]}


def tshark_live(runner, interface: str = "", filter_expr: str = "",
                count: int = 50, duration: int = 15, timeout: int = 120) -> Dict[str, Any]:
    args = []
    if interface:
        args.extend(["-i", interface])
    if filter_expr:
        args.extend(["-Y", filter_expr])
    args.extend(["-c", str(int(count)), "-a", "duration:" + str(int(duration))])

    code = _hdr() + (
        "\nargs = [TOOLS['tshark']] + " + _s(args) + "\n"
        "iface = " + _s(interface) + "\n"
        "if not iface and '-i' in args:\n"
        "    rc0, o0, e0 = run([TOOLS['tshark'], '-D'], timeout=30)\n"
        "    import re as _re\n"
        "    for ln in (o0 or '').splitlines():\n"
        "        m = _re.match(r'\\s*(\\d+)\\.\\s+(\\S+)', ln)\n"
        "        if m:\n"
        "            args[args.index('-i') + 1] = m.group(2)\n"
        "            iface = m.group(2)\n"
        "            break\n"
        "rc, out, err = run(args, " + _inner(timeout, 30) + ")\n"
        "pk = [l for l in (out or '').splitlines() if l.strip()]\n"
        "emit({'rc': rc, 'iface': iface, 'args': args, 'packets': pk[:400],\n"
        "      'err': (err or '')[:400]})\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "tshark", "error": res.get("error"),
                "raw": res.get("raw", "")[:1500]}
    d = res["data"]
    pkts = d.get("packets") or []
    return {"ok": True, "tool": "tshark", "interface": d.get("iface"),
            "packet_count": len(pkts), "packets": pkts[:200],
            "args": d.get("args", []), "error": d.get("err", "")}


# ---------------------------------------------------------------------------
# 13. Python 生态
# ---------------------------------------------------------------------------
def python_analyze(runner, target: str, timeout: int = 300) -> Dict[str, Any]:
    """pefile + lief 综合画像。pefile 不用 fast_load，否则导入表为空。"""
    code = _hdr() + (
        "\nimport hashlib\n"
        "target = " + _s(target) + "\n"
        "r = {'target': target}\n"
        "try:\n"
        "    import pefile\n"
        "    pe = pefile.PE(target)\n"
        "    r['machine'] = hex(pe.FILE_HEADER.Machine)\n"
        "    r['timestamp'] = pe.FILE_HEADER.TimeDateStamp\n"
        "    r['subsystem'] = getattr(pe.OPTIONAL_HEADER, 'Subsystem', None)\n"
        "    r['entrypoint'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)\n"
        "    r['imagebase'] = hex(pe.OPTIONAL_HEADER.ImageBase)\n"
        "    secs = []\n"
        "    for s in pe.sections:\n"
        "        secs.append({'name': s.Name.rstrip(b'\\x00').decode('latin1'),\n"
        "                     'va': hex(s.VirtualAddress),\n"
        "                     'vsize': s.Misc_VirtualSize,\n"
        "                     'rawsize': s.SizeOfRawData,\n"
        "                     'entropy': round(s.get_entropy(), 2)})\n"
        "    r['sections'] = secs\n"
        "    imps = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) or []\n"
        "    r['imports_count'] = len(imps)\n"
        "    r['import_dlls'] = [d.dll.decode('latin1', 'replace') for d in imps][:30]\n"
        "    r['has_signature'] = bool(getattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY', None)\n"
        "                              and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size > 0)\n"
        "except Exception as e:\n"
        "    r['pefile_error'] = str(e)[:300]\n"
        "try:\n"
        "    import lief\n"
        "    b = lief.parse(target)\n"
        "    if b is not None:\n"
        "        r['lief_format'] = str(b.format).split('.')[-1]\n"
        "        r['lief_entrypoint'] = hex(b.entrypoint)\n"
        "        r['lief_libraries'] = list(getattr(b, 'libraries', []))[:20]\n"
        "except Exception as e:\n"
        "    r['lief_error'] = str(e)[:200]\n"
        "try:\n"
        "    data = open(target, 'rb').read()\n"
        "    r['md5'] = hashlib.md5(data).hexdigest()\n"
        "    r['sha1'] = hashlib.sha1(data).hexdigest()\n"
        "    r['sha256'] = hashlib.sha256(data).hexdigest()\n"
        "    r['size'] = len(data)\n"
        "except Exception as e:\n"
        "    r['hash_error'] = str(e)[:200]\n"
        "emit(r)\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "python-analyze", "error": res.get("error"),
                "raw": res.get("raw", "")[:1500]}
    d = res["data"]
    d["ok"] = bool(d.get("sections")) or ("pefile_error" not in d)
    d["tool"] = "python-analyze"
    return d


def angr_cfg(runner, target: str, timeout: int = 900,
             max_blocks: int = 200) -> Dict[str, Any]:
    """angr 控制流图（慢，大文件慎用）。"""
    code = _hdr() + (
        "\ntarget = " + _s(target) + "\n"
        "r = {'target': target}\n"
        "try:\n"
        "    import angr\n"
        "    p = angr.Project(target, auto_load_libs=False)\n"
        "    cfg = p.analyses.CFGFast()\n"
        "    r['arch'] = p.arch.name\n"
        "    r['entry'] = hex(p.entry)\n"
        "    r['function_count'] = len(cfg.functions)\n"
        "    try:\n"
        "        r['callgraph_edges'] = cfg.callgraph.number_of_edges()\n"
        "    except Exception:\n"
        "        r['callgraph_edges'] = -1\n"
        "    fns = []\n"
        "    for addr, f in list(cfg.functions.items())[:" + str(int(max_blocks)) + "]:\n"
        "        fns.append({'addr': hex(addr), 'name': f.name,\n"
        "                    'blocks': len(list(f.blocks))})\n"
        "    r['functions'] = fns\n"
        "except Exception as e:\n"
        "    r['error'] = str(e)[:500]\n"
        "emit(r)\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "angr", "error": res.get("error"),
                "raw": res.get("raw", "")[:1500]}
    d = res["data"]
    d["ok"] = "error" not in d
    d["tool"] = "angr-cfg"
    return d


def oletools_scan(runner, target: str, timeout: int = 300) -> Dict[str, Any]:
    """oletools 扫描 Office 文档（VBA 宏）。"""
    code = _hdr() + (
        "\ntarget = " + _s(target) + "\n"
        "r = {'target': target}\n"
        "try:\n"
        "    rc, out, err = run(['C:\\\\Python313\\\\python.exe', '-m',\n"
        "                        'oletools.olevba', '--reveal', target], " +
        _inner(timeout, 60) + ")\n"
        "    r['rc'] = rc\n"
        "    r['vba'] = ((out or '') + (err or ''))[:6000]\n"
        "except Exception as e:\n"
        "    r['error'] = str(e)[:300]\n"
        "emit(r)\n"
    )
    res = _guest_call(runner, code, timeout=timeout)
    if not res["ok"]:
        return {"ok": False, "tool": "oletools", "error": res.get("error"),
                "raw": res.get("raw", "")[:1500]}
    d = res["data"]
    d["ok"] = "error" not in d
    d["tool"] = "oletools"
    return d


# ---------------------------------------------------------------------------
# 汇总画像
# ---------------------------------------------------------------------------
def triage(runner, target: str, timeout: int = 600) -> Dict[str, Any]:
    """一站式样本画像：PE 结构 + 查壳 + 签名 + capa。"""
    out: Dict[str, Any] = {"target": target, "steps": {}}
    steps = out["steps"]

    def safe(name, fn, *a, **kw):
        try:
            steps[name] = fn(runner, *a, **kw)
        except Exception as e:
            steps[name] = {"ok": False, "error": str(e)[:300]}

    safe("pe", python_analyze, target, timeout=min(240, timeout))
    safe("die", die_detect, target, timeout=120)
    safe("sigcheck", sigcheck_verify, target, timeout=120)
    safe("capa", capa_analyze, target, timeout=max(180, timeout - 200))

    out["ok"] = True
    return out
