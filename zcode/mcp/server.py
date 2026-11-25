#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seep-ZCode 本地工具桥 MCP 服务端

作用：把本机已装的逆向工具（jadx / apktool / radare2 / frida / tshark / ffmpeg /
IDA / Ghidra）统一暴露成 MCP 工具，供 ZCode 全自动调用。

设计要点
  - 纯 stdlib + mcp 库，无第三方依赖
  - 工具路径从 mcp/tools.ini 读，缺哪个就报哪个（不静默失败）
  - 每个工具都做 startup 自检，seep_doctor 一把列出全部状态
  - 输出统一截断到 MAX_OUTPUT 字符，避免撑爆上下文

与 seep 的关系
  seep 的 38 个工具做大而全的编排；本服务只做「把本机工具接上 MCP」这件事，
  两者可以并存，也可以只用其中一个。
"""

import os
import re
import sys
import json
import glob
import shutil
import subprocess
import platform
from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer
    except ImportError:
        print("ERROR: 需要 mcp 库。请用装有 mcp 的 python 运行本服务。", file=sys.stderr)
        raise

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
INI_PATH = HERE / "tools.ini"
MAX_OUTPUT = int(os.environ.get("SEEP_MAX_OUTPUT", "40000"))
DEFAULT_TIMEOUT = int(os.environ.get("SEEP_TIMEOUT", "600"))

# 知识库根目录（从上游 ReverseLab 合并进来，292 篇战术文档）
# 优先级：环境变量 SEEP_KB_DIR > 插件内 kb/
_KB_CANDIDATES = [
    os.environ.get("SEEP_KB_DIR", ""),
    str(HERE.parent / "kb"),
]
KB_DIR = next((p for p in _KB_CANDIDATES if p and os.path.isdir(p)), _KB_CANDIDATES[1])

# GDB stub 客户端（同目录模块）
sys.path.insert(0, str(HERE))
try:
    from gdbstub import GdbStubClient, GdbError, hexdump, format_regs
    HAS_GDB = True
except Exception as _e:  # 模块缺失不应让整个服务起不来
    HAS_GDB = False
    _GDB_IMPORT_ERROR = str(_e)

# vmrun 执行通道
try:
    from vmrun import VmRunner, VmError
    HAS_VMRUN = True
except Exception as _e2:
    HAS_VMRUN = False
    _VMRUN_IMPORT_ERROR = str(_e2)

# VM 内工具专用封装（结构化层）
try:
    import vmtools
    HAS_VMTOOLS = True
except Exception as _e3:
    HAS_VMTOOLS = False
    _VMTOOLS_IMPORT_ERROR = str(_e3)

# 上游 seep 工具集（从 ReverseLab 合并：r2 降噪 / apk / 工作流）
try:
    import upstream_tools as up
    HAS_UPSTREAM = True
except Exception as _e4:
    HAS_UPSTREAM = False
    _UPSTREAM_IMPORT_ERROR = str(_e4)


def _expand(value: str) -> str:
    if not value:
        return value
    v = os.path.expandvars(value)
    if v.startswith("~"):
        v = os.path.join(os.path.expanduser("~"), v[1:].lstrip("/\\"))
    return v


def load_config() -> Dict[str, Dict[str, str]]:
    """极简 INI 解析（不引 configparser 的插值坑）。"""
    cfg: Dict[str, Dict[str, str]] = {}
    if not INI_PATH.is_file():
        return cfg
    section = "default"
    with open(INI_PATH, "r", encoding="utf-8-sig") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                cfg.setdefault(section, {})
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                cfg.setdefault(section, {})[k.strip().lower()] = _expand(v.strip())
    return cfg


CFG = load_config()


def cfg_get(section: str, key: str, default: str = "") -> str:
    return CFG.get(section, {}).get(key, default)


# ---------------------------------------------------------------------------
# Java 环境
# ---------------------------------------------------------------------------
def ensure_java_env() -> str:
    """把配置里的 JDK 挂到 JAVA_HOME / PATH。

    jadx.bat 与 apktool 都依赖 JAVA_HOME 或 PATH 里的 java；
    本机 JDK 装在非标准位置且未进 PATH，所以这里显式补上。
    返回 java 可执行文件路径（可能为空）。
    """
    java = cfg_get("machine", "java")
    if not java or not os.path.isfile(java):
        found = shutil.which("java")
        if found:
            java = found
        else:
            return ""
    java_home = str(Path(java).resolve().parent.parent)
    os.environ["JAVA_HOME"] = java_home
    jbin = str(Path(java).resolve().parent)
    parts = os.environ.get("PATH", "").split(os.pathsep)
    if jbin not in parts:
        os.environ["PATH"] = jbin + os.pathsep + os.environ.get("PATH", "")
    return java


JAVA_EXE = ensure_java_env()


# ---------------------------------------------------------------------------
# 工具解析：配置路径 → 系统 PATH
# ---------------------------------------------------------------------------
def resolve_tool(section: str, key: str) -> Optional[str]:
    explicit = cfg_get(section, key)
    if explicit:
        # apktool 是 jar，单独判断
        if os.path.isfile(explicit):
            return explicit
    for name in (key, f"{key}.exe", f"{key}.bat", f"{key}.cmd"):
        found = shutil.which(name)
        if found:
            return found
    return None


def run(cmd: List[str], timeout: int = DEFAULT_TIMEOUT, cwd: Optional[str] = None,
        limit: Optional[int] = -1) -> Dict[str, Any]:
    """统一执行入口，返回 {ok, code, stdout, stderr, cmd}。

    limit: 输出截断上限。
        -1（默认）= 用 MAX_OUTPUT
         None     = 不截断（解析 JSON 时必须用这个，截断会导致 JSONDecodeError）
         其他整数 = 用该值
    """
    cap = MAX_OUTPUT if limit == -1 else limit
    try:
        p = subprocess.run(
            cmd, capture_output=True, timeout=timeout, cwd=cwd,
            encoding="utf-8", errors="replace",
        )
        so = p.stdout or ""
        se = p.stderr or ""
        if cap is not None:
            so = so[:cap]
            se = se[:cap]
        return {
            "ok": p.returncode == 0,
            "code": p.returncode,
            "stdout": so,
            "stderr": se,
            "cmd": " ".join(cmd),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": -1, "stdout": "", "stderr": f"超时（{timeout}s）", "cmd": " ".join(cmd)}
    except FileNotFoundError:
        return {"ok": False, "code": -2, "stdout": "", "stderr": f"找不到可执行文件: {cmd[0]}", "cmd": " ".join(cmd)}
    except Exception as e:
        return {"ok": False, "code": -3, "stdout": "", "stderr": str(e), "cmd": " ".join(cmd)}


def emit(result: Dict[str, Any]) -> str:
    """把执行结果压成可读文本（优先 stdout，失败附带 stderr）。"""
    if result["ok"]:
        return result["stdout"] or "(无输出)"
    return "命令: %s\n退出码: %s\n--- stdout ---\n%s\n--- stderr ---\n%s" % (
        result["cmd"], result["code"], result["stdout"], result["stderr"])


# ---------------------------------------------------------------------------
# MCP 服务
# ---------------------------------------------------------------------------
mcp = MCPServer("seep-zcode")

# 把宿主上下文注入 upstream_tools（路径解析 / 命令执行 / 知识库位置）
if HAS_UPSTREAM:
    up.set_context(
        resolve_tool=resolve_tool,
        run=run,
        KB_DIR=KB_DIR,
        BASE_DIR=str(HERE.parent),
        JAVA_EXE=JAVA_EXE,
    )


@mcp.tool()
def seep_doctor() -> str:
    """体检：列出本机所有逆向工具的可达状态、版本与路径。

    出问题先跑这个。返回每个工具的 READY / MISSING / DEGRADED 状态。
    """
    lines = ["Seep-ZCode 工具体检", "=" * 60, ""]

    py = cfg_get("machine", "python") or sys.executable
    java = JAVA_EXE or cfg_get("machine", "java") or resolve_tool("machine", "java")

    checks = []

    # Python
    checks.append(("python", py if os.path.isfile(py) else resolve_tool("machine", "python"),
                   [py, "-c", "import mcp; print('mcp', mcp.__version__ if hasattr(mcp,'__version__') else 'ok')"]))
    # Java
    if java:
        checks.append(("java", java, [java, "-version"]))

    for key in ("jadx", "apktool", "radare2", "rabin2", "radiff2", "rahash2", "rasm2", "ida", "tshark", "ffmpeg", "ffprobe"):
        path = resolve_tool("paths", key)
        if not path:
            checks.append((key, None, None))
            continue
        if key == "apktool":
            checks.append((key, path, [java, "-jar", path, "--version"] if java else None))
        elif key in ("radare2", "rabin2", "radiff2", "rahash2", "rasm2"):
            checks.append((key, path, [path, "-v"]))
        elif key in ("tshark", "ffmpeg", "ffprobe"):
            checks.append((key, path, [path, "-v"] if key == "tshark" else [path, "-version"]))
        else:
            checks.append((key, path, [path, "--version"] if key == "jadx" else None))

    for name, path, verify_cmd in checks:
        if not path:
            lines.append("[MISSING ] %-10s 未找到" % name)
            continue
        if verify_cmd is None:
            lines.append("[READY   ] %-10s %s" % (name, path))
            continue
        r = run(verify_cmd, timeout=25)
        first = (r["stdout"] or r["stderr"] or "").strip().splitlines()
        ver = first[0][:90] if first else ""
        tag = "READY   " if r["ok"] else "DEGRADED"
        lines.append("[%s] %-10s %s" % (tag, name, path))
        if ver:
            lines.append("           %s" % ver)

    # frida（python 包，不是 exe）
    fr = run([py, "-c", "import frida;print(frida.__version__)"], timeout=25)
    if fr["ok"]:
        lines.append("[READY   ] %-10s frida %s (python 包)" % ("frida", fr["stdout"].strip()))
    else:
        lines.append("[MISSING ] %-10s 未安装 frida python 包" % "frida")

    # 外部 HTTP 服务
    lines.append("")
    lines.append("--- 外部 MCP 服务 ---")
    import socket
    for label, host_key in (("x64dbg", "x64dbg_x64"), ("x32dbg", "x64dbg_x86"), ("ghidra", "ghidra")):
        url = cfg_get("services", host_key)
        if not url:
            continue
        m = re.match(r"https?://([^:/]+):(\d+)", url)
        if not m:
            continue
        host, port = m.group(1), int(m.group(2))
        s = socket.socket()
        s.settimeout(1.5)
        try:
            s.connect((host, port))
            lines.append("[ONLINE  ] %-10s %s" % (label, url))
        except Exception:
            lines.append("[OFFLINE ] %-10s %s （未启动）" % (label, url))
        finally:
            s.close()

    # 虚拟机
    vm = cfg_get("vm", "host")
    if vm:
        lines.append("")
        lines.append("--- 虚拟机 %s ---" % vm)
        for key, label in (("x64dbg_port", "x64dbg"), ("x32dbg_port", "x32dbg"), ("ida_port", "ida")):
            port_s = cfg_get("vm", key)
            if not port_s.isdigit():
                continue
            port = int(port_s)
            s = socket.socket()
            s.settimeout(1.5)
            try:
                s.connect((vm, port))
                lines.append("[ONLINE  ] %-10s %s:%d" % (label, vm, port))
            except Exception:
                lines.append("[OFFLINE ] %-10s %s:%d （服务未监听）" % (label, vm, port))
            finally:
                s.close()

    # GDB 内核调试 stub
    lines.append("")
    lines.append("--- GDB 内核调试 stub ---")
    if not HAS_GDB:
        lines.append("[MISSING ] %-10s 模块加载失败: %s" % ("gdbstub", _GDB_IMPORT_ERROR))
    else:
        gb_host = cfg_get("gdb", "host") or "127.0.0.1"
        gb_port_s = cfg_get("gdb", "port") or "8864"
        gb_port = int(gb_port_s) if gb_port_s.isdigit() else 8864
        s = socket.socket()
        s.settimeout(1.5)
        try:
            s.connect((gb_host, gb_port))
            lines.append("[ONLINE  ] %-10s %s:%d （%s）" % ("gdbstub", gb_host, gb_port, "VMware 内核调试"))
        except Exception:
            lines.append("[OFFLINE ] %-10s %s:%d （虚拟机未开或 debugStub 未启用）"
                         % ("gdbstub", gb_host, gb_port))
        finally:
            s.close()

    return "\n".join(lines)


@mcp.tool()
def seep_r2_info(binary_path: str) -> str:
    """提取二进制关键元信息：架构、位数、大小、端序、编译器，以及安全机制
    （Canary / NX / PIE / RELRO / ASLR）。

    Args:
        binary_path: 目标文件路径（PE/ELF/Mach-O 皆可）
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.r2_info(binary_path)


@mcp.tool()
def seep_r2_cmd(binary_path: str, command: str, analyze: bool = True, timeout: int = 90) -> str:
    """在目标上执行任意 radare2 命令。

    Args:
        binary_path: 目标文件路径
        command: r2 命令（如 'afl'、'pdf @ main'、'iz'、'px 64 @ 0x1000'，多条用分号）
        analyze: 是否先跑 aaa 分析，默认 True
        timeout: 超时秒数
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.r2_cmd(binary_path, command, analyze=analyze, timeout=timeout)


@mcp.tool()
def seep_r2_strings(binary_path: str, filter_text: str = "",
                    all_sections: bool = False, limit: int = 100) -> str:
    """提取字符串，支持关键词过滤与全段检索。

    Args:
        binary_path: 目标文件路径
        filter_text: 关键词过滤（不区分大小写）
        all_sections: True 用 -zz 检索全段；False 只查数据段
        limit: 最多返回行数
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.r2_strings(binary_path, filter_text=filter_text,
                         all_sections=all_sections, limit=limit)


@mcp.tool()
def seep_r2_functions(binary_path: str, filter_name: str = "", limit: int = 100) -> str:
    """列出函数、入口点与导入导出符号。

    Args:
        binary_path: 目标文件路径
        filter_name: 按名称过滤（不区分大小写）
        limit: 最大返回行数
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.r2_functions(binary_path, filter_name=filter_name, limit=limit)


@mcp.tool()
def seep_r2_disasm(binary_path: str, target: str = "main", lines: int = 60,
                   output_mode: str = "full", limit_tokens: int = 0) -> str:
    """反汇编指定函数/地址，支持三档降噪模式（控制上下文消耗）。

    Args:
        binary_path: 目标文件路径
        target: 函数名、符号或地址（'main' / 'sym.imp.puts' / '0x1013ef0'）
        lines: 以地址为目标时的最大指令行数
        output_mode:
            'full'    完整反汇编（默认）
            'branch'  仅保留 cmp/test/jcc/call/ret —— 控制流骨架
            'summary' 只给函数信息 + 调用方/被调用方统计（最省 Token）
        limit_tokens: 最大字符数（0=不限）
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.r2_disasm(binary_path, target=target, lines=lines,
                        output_mode=output_mode, limit_tokens=limit_tokens)


@mcp.tool()
def seep_r2_decompile(binary_path: str, target: str = "main",
                      output_mode: str = "full", limit_tokens: int = 8000) -> str:
    """反编译为类 C 伪代码，支持三档降噪。

    Args:
        binary_path: 目标文件路径
        target: 函数名或地址
        output_mode:
            'full'    完整伪代码（默认）
            'fold'    折叠纯赋值/计算，只留 if/else/switch/return/调用（省约 60%）
            'summary' 只给函数签名与调用关系（最省）
        limit_tokens: 最大字符数（默认 8000，0=不限）
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.r2_decompile(binary_path, target=target,
                           output_mode=output_mode, limit_tokens=limit_tokens)


@mcp.tool()
def seep_r2_xrefs(binary_path: str, target: str, direction: str = "to", limit: int = 10) -> str:
    """交叉引用查询（带分页与统计摘要，避免上下文爆炸）。

    Args:
        binary_path: 目标文件路径
        target: 函数名或地址
        direction: 'to' 谁引用了它（调用方）/ 'from' 它引用了谁
        limit: 最多返回条数
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.r2_xrefs(binary_path, target, direction=direction, limit=limit)


@mcp.tool()
def seep_r2_diff(file_a: str, file_b: str, mode: str = "code") -> str:
    """用 radiff2 比对两个二进制的差异（适合补丁前后对比）。

    Args:
        file_a: 第一个文件
        file_b: 第二个文件
        mode: 'code' 函数代码比对 / 'hex' 十六进制 / 'stats' 差异摘要
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.r2_diff(file_a, file_b, mode=mode)


@mcp.tool()
def seep_r2_asm(code_or_hex: str, arch: str = "x86", bits: int = 64, disasm: bool = False) -> str:
    """汇编 / 反汇编单条或多条指令（rasm2）。

    Args:
        code_or_hex: 汇编文本（'xor eax, eax; ret'）或 hex（'31c0c3'）
        arch: 架构（x86 / arm / mips / riscv）
        bits: 位数（16 / 32 / 64）
        disasm: True 把 hex 转汇编；False 把汇编转 hex
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.r2_asm(code_or_hex, arch=arch, bits=bits, disasm=disasm)


@mcp.tool()
def seep_apk_info(apk_path: str) -> str:
    """原生解析 APK 结构（免 Java）：DEX 数量、native 架构、签名证书、Manifest 关键标记。

    Args:
        apk_path: APK 文件路径
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.apk_info(apk_path)


@mcp.tool()
def seep_apk_decompile(apk_path: str, output_dir: str = "",
                       deobfuscate: bool = True, timeout: int = 900) -> str:
    """用 jadx 把 APK/DEX 反编译为 Java 源码工程。

    Args:
        apk_path: APK 或 DEX 路径
        output_dir: 输出目录（留空则在 APK 旁建 <name>_jadx_src）
        deobfuscate: 是否反混淆（--deobf）
        timeout: 超时秒数
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.apk_decompile(apk_path, output_dir=output_dir,
                            deobfuscate=deobfuscate, timeout=timeout)


@mcp.tool()
def seep_apk_unpack(apk_path: str, output_dir: str = "", no_src: bool = False,
                    timeout: int = 600) -> str:
    """用 apktool 解包 APK：资源、明文 Manifest、Smali 代码。

    Args:
        apk_path: APK 路径
        output_dir: 输出目录（留空则在 APK 旁建 <name>_apktool）
        no_src: True 跳过 smali（只提资源）
        timeout: 超时秒数
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.apk_unpack(apk_path, output_dir=output_dir,
                         no_src=no_src, timeout=timeout)


@mcp.tool()
def seep_apk_smali_search(directory: str, pattern: str,
                          case_sensitive: bool = False, limit: int = 50) -> str:
    """在 smali/源码目录里正则搜索（找密钥、签名、URL、鉴权关键字）。

    Args:
        directory: 解包后的 smali 或源码根目录
        pattern: 正则或文本（'AES' / 'SecretKeySpec' / 'token' / 'http://'）
        case_sensitive: 是否大小写敏感
        limit: 最多返回条数
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.apk_smali_search(directory, pattern,
                               case_sensitive=case_sensitive, limit=limit)


@mcp.tool()
def seep_apk_gen_hook(framework: str = "frida", class_name: str = "com.example.app.MainActivity",
                      method_name: str = "checkFlag", param_types: str = "",
                      return_type: str = "boolean", hook_timing: str = "after") -> str:
    """按类名/方法签名生成 Hook 脚本（Frida JS 或 LSPosed BeanShell）。

    Args:
        framework: 'frida'（默认）或 'bsh'/'lsposed'
        class_name: 完整类名（com.example.app.SecurityHelper）
        method_name: 方法名（verifyLicense）
        param_types: 形参类型，逗号分隔（'java.lang.String,int'），重载方法才需要
        return_type: 返回类型（boolean/void/int/...）
        hook_timing: 'before' / 'after' / 'replace'
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    params = [p.strip() for p in param_types.split(",") if p.strip()] if param_types else []
    return up.apk_gen_hook(framework=framework, class_name=class_name,
                           method_name=method_name, param_types=params,
                           return_type=return_type, hook_timing=hook_timing)


@mcp.tool()
def seep_status() -> str:
    """检查 seep 工具链状态（r2 / rabin2 / jadx / apktool / java / 知识库）。"""
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.status()


@mcp.tool()
def seep_task_init(task_name: str, description: str = "") -> str:
    """为任务创建规范工作区（samples/exports/patches/reports），避免产物乱堆。

    Args:
        task_name: 任务名（会净化成合法目录名）
        description: 任务描述，写进 README
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.task_init(task_name, description=description)


@mcp.tool()
def seep_auto_triage(target_path: str, task_name: str = "") -> str:
    """一键侦察：哈希 + 架构/安全机制 + 鉴权类高价值字符串采样。

    Args:
        target_path: 目标文件（PE/DLL/APK/ELF）
        task_name: 若给了且工作区存在，报告会存进 reports/
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.auto_triage(target_path, task_name=task_name)


@mcp.tool()
def seep_ida_status() -> str:
    """探测本机 IDA MCP 是否在线（13337/13338）。"""
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.ida_status()


@mcp.tool()
def seep_gen_security_report(task_name: str, target_name: str,
                             vuln_type: str = "CWE-602: 客户端鉴权与状态判定缺陷",
                             branch_location: str = "0x0", description: str = "",
                             poc_summary: str = "", defense_recommendation: str = "") -> str:
    """生成安全评估报告，落到 <task>/reports/。

    Args:
        task_name: 任务工作区名（需先 seep_task_init）
        target_name: 目标资产名
        vuln_type: 缺陷分类
        branch_location: 判定函数 / 偏移
        description: 风险描述
        poc_summary: PoC 验证摘要
        defense_recommendation: 加固建议（留空用默认模板）
    """
    if not HAS_UPSTREAM:
        return "上游工具模块未加载: %s" % _UPSTREAM_IMPORT_ERROR
    return up.gen_security_report(task_name, target_name, vuln_type=vuln_type,
                                  branch_location=branch_location,
                                  description=description, poc_summary=poc_summary,
                                  defense_recommendation=defense_recommendation)


@mcp.tool()
def seep_jadx_decompile(apk_path: str, out_dir: str = "", threads: int = 4, timeout: int = 900) -> str:
    """用 jadx 反编译 APK / DEX / JAR。

    Args:
        apk_path: APK 文件路径
        out_dir: 输出目录（留空则输出到 <同名>_jadx）
        threads: 并行线程数
        timeout: 超时秒数（大 APK 可能要几分钟）
    """
    jadx = resolve_tool("paths", "jadx")
    if not jadx:
        return "jadx 不可用"
    java = JAVA_EXE or cfg_get("machine", "java")
    if not out_dir:
        out_dir = os.path.splitext(apk_path)[0] + "_jadx"

    cmd = [jadx, "-d", out_dir, "-j", str(threads), apk_path]
    res = run(cmd, timeout=timeout)
    if res["ok"]:
        n = sum(len(f) for _, _, f in os.walk(out_dir)) if os.path.isdir(out_dir) else 0
        return "反编译完成 -> %s\n生成文件数: %d" % (out_dir, n)
    return emit(res)


@mcp.tool()
def seep_apktool_decode(apk_path: str, out_dir: str = "", no_src: bool = False, timeout: int = 600) -> str:
    """用 apktool 解包 APK（资源 + smali）。

    Args:
        apk_path: APK 文件路径
        out_dir: 输出目录（留空则用 apktool 默认）
        no_src: True 时只解资源，不反编译 smali
        timeout: 超时秒数
    """
    jar = resolve_tool("paths", "apktool")
    java = cfg_get("machine", "java") or "java"
    if not jar:
        return "apktool.jar 不可用"
    cmd = [java, "-jar", jar, "d", apk_path, "-f"]
    if out_dir:
        cmd += ["-o", out_dir]
    if no_src:
        cmd.append("-s")
    res = run(cmd, timeout=timeout)
    return emit(res)


@mcp.tool()
def seep_apktool_build(decoded_dir: str, out_apk: str = "", timeout: int = 600) -> str:
    """用 apktool 回编译并打包 APK。

    Args:
        decoded_dir: apktool 解包出来的目录
        out_apk: 输出 APK 路径
        timeout: 超时秒数
    """
    jar = resolve_tool("paths", "apktool")
    java = cfg_get("machine", "java") or "java"
    if not jar:
        return "apktool.jar 不可用"
    cmd = [java, "-jar", jar, "b", decoded_dir]
    if out_apk:
        cmd += ["-o", out_apk]
    res = run(cmd, timeout=timeout)
    return emit(res)


@mcp.tool()
def seep_frida_devices() -> str:
    """列出 Frida 可连接的设备（USB / 远程 / 本机）。

    安卓真机或模拟器需先跑 frida-server。
    """
    py = cfg_get("machine", "python") or sys.executable
    code = "import frida,sys;[print(d.id, '|', d.name, '|', d.type) for d in frida.enumerate_devices()]"
    res = run([py, "-c", code], timeout=60)
    return emit(res)


@mcp.tool()
def seep_frida_ps(device_id: str = "", running_only: bool = True) -> str:
    """列出设备上的进程，用于定位 hook 目标。

    Args:
        device_id: frida 设备 ID（留空用 USB 设备）
        running_only: True 只看正在运行的
    """
    py = cfg_get("machine", "python") or sys.executable
    code = (
        "import frida\n"
        "devs=frida.enumerate_devices()\n"
        f"did={device_id!r}\n"
        "dev=[d for d in devs if d.id==did][0] if did else (devs[0] if devs else None)\n"
        "if not dev: print('NO_DEVICE'); raise SystemExit\n"
        f"procs=dev.enumerate_processes()\n"
        "print('device:', dev.id, dev.name)\n"
        f"for p in procs[:400]: print(p.pid, p.name)\n"
    )
    res = run([py, "-c", code], timeout=120)
    return emit(res)


@mcp.tool()
def seep_frida_run_script(script_path: str, target: str = "", device_id: str = "", spawn: bool = False,
                          duration: int = 30) -> str:
    """在设备上运行 Frida 脚本，采集一段时间的输出。

    Args:
        script_path: 本地 .js 脚本路径
        target: 目标应用包名或进程名
        device_id: frida 设备 ID（留空用 USB）
        spawn: True 则 spawn 方式启动（更早 hook）
        duration: 运行多少秒后自动 detach 并返回输出
    """
    py = cfg_get("machine", "python") or sys.executable
    code = f"""
import frida, sys, time, threading

script_src = open({script_path!r}, 'r', encoding='utf-8').read()
devs = frida.enumerate_devices()
did = {device_id!r}
dev = [d for d in devs if d.id == did][0] if did else (devs[0] if devs else None)
if not dev:
    print('NO_DEVICE'); raise SystemExit(1)

target = {target!r}
logs = []

def on_message(msg, data):
    if msg.get('type') == 'send':
        logs.append(str(msg.get('payload')))
    elif msg.get('type') == 'error':
        logs.append('ERROR: ' + str(msg.get('description')))

session = None
try:
    if {str(spawn)}:
        pid = dev.spawn([target] if isinstance(target, str) else target)
        session = dev.attach(pid)
        script = session.create_script(script_src)
        script.on('message', on_message)
        script.load()
        dev.resume(pid)
    else:
        session = dev.attach(target)
        script = session.create_script(script_src)
        script.on('message', on_message)
        script.load()
    time.sleep({duration})
finally:
    try:
        if session: session.detach()
    except Exception:
        pass

print('--- captured %d lines ---' % len(logs))
for line in logs[:800]:
    print(line)
"""
    res = run([py, "-c", code], timeout=duration + 120)
    return emit(res)


@mcp.tool()
def seep_tshark_capture(interface: str = "", filter_expr: str = "", count: int = 50,
                        duration: int = 20, out_pcap: str = "") -> str:
    """用 tshark 抓包并输出摘要。

    Args:
        interface: 网卡名（留空用 tshark -D 的第一个）
        filter_expr: 显示过滤器，如 "http.request"
        count: 抓多少个包
        duration: 最长抓多少秒
        out_pcap: 同时保存 pcap 的路径（可空）
    """
    tshark = resolve_tool("paths", "tshark")
    if not tshark:
        return "tshark 不可用"
    if not interface:
        d = run([tshark, "-D"], timeout=30)
        if d["ok"]:
            for line in d["stdout"].splitlines():
                m = re.match(r"\s*(\d+)\.\s+(\S+)", line)
                if m:
                    interface = m.group(2)
                    break
    if not interface:
        return "未找到可用网卡，请手动指定 interface"
    cmd = [tshark, "-i", interface, "-c", str(count), "-a", f"duration:{duration}"]
    if filter_expr:
        cmd += ["-Y", filter_expr]
    if out_pcap:
        cmd += ["-w", out_pcap]
    res = run(cmd, timeout=duration + 90)
    return emit(res)


@mcp.tool()
def seep_tshark_read(pcap_path: str, filter_expr: str = "", limit: int = 200) -> str:
    """读取并解析已有 pcap 文件。

    Args:
        pcap_path: pcap 文件路径
        filter_expr: 显示过滤器
        limit: 最多输出行数
    """
    tshark = resolve_tool("paths", "tshark")
    if not tshark:
        return "tshark 不可用"
    cmd = [tshark, "-r", pcap_path]
    if filter_expr:
        cmd += ["-Y", filter_expr]
    cmd += ["-c", str(limit)]
    res = run(cmd, timeout=180)
    return emit(res)


@mcp.tool()
def seep_pe_info(path: str) -> str:
    """用内置 Python 解析 PE 文件头（不依赖 pefile，纯 stdlib）。

    返回：机器类型、节区、入口点、导入表、是否带签名。

    Args:
        path: PE 文件路径
    """
    import struct
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return f"读取失败: {e}"
    if data[:2] != b"MZ":
        return "不是 PE 文件（缺少 MZ 头）"
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b"PE\0\0":
            return "PE 签名缺失"
        machine, nsec = struct.unpack_from("<HH", data, pe_off + 4)
        opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        opt_off = pe_off + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        is64 = magic == 0x20B
        entry = struct.unpack_from("<I", data, opt_off + 16)[0]
        image_base = struct.unpack_from("<Q" if is64 else "<I", data, opt_off + (24 if is64 else 28))[0]

        machines = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1C4: "ARM"}
        out = [
            "文件: %s" % path,
            "架构: %s (%s)" % (machines.get(machine, hex(machine)), "PE32+" if is64 else "PE32"),
            "入口点: RVA 0x%X  (VA 0x%X)" % (entry, image_base + entry),
            "节区数: %d" % nsec,
            "",
            "%-10s %-10s %-10s %-10s %s" % ("名称", "VA", "虚拟大小", "原始大小", "熵/特征"),
        ]
        sec_off = opt_off + opt_size
        import math
        for i in range(nsec):
            o = sec_off + i * 40
            name = data[o:o + 8].rstrip(b"\0").decode("latin1", "replace")
            vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, o + 8)
            sec_data = data[raddr:raddr + rsize][:65536] if rsize else b""
            ent = 0.0
            if sec_data:
                from collections import Counter
                c = Counter(sec_data)
                ent = -sum((n / len(sec_data)) * math.log2(n / len(sec_data)) for n in c.values())
            flags = []
            if ent > 7.2:
                flags.append("高熵(可能加壳/加密)")
            if vsize == 0:
                flags.append("空节(可疑)")
            out.append("%-10s 0x%-8X 0x%-8X 0x%-8X %.2f %s" % (name, vaddr, vsize, rsize, ent, ",".join(flags)))

        # 签名目录
        dd_off = opt_off + (112 if is64 else 96)
        try:
            sec_dd_rva, sec_dd_size = struct.unpack_from("<II", data, dd_off + 4 * 8)
            out.append("")
            out.append("数字签名: %s" % ("有 (大小 %d 字节)" % sec_dd_size if sec_dd_size else "无"))
        except Exception:
            pass
        return "\n".join(out)
    except Exception as e:
        return "解析失败: %s" % e


def _gdb_client(timeout: Optional[float] = None):
    """按配置创建 GDB 客户端（未连接）。"""
    if not HAS_GDB:
        raise RuntimeError("gdbstub 模块未加载: %s" % _GDB_IMPORT_ERROR)
    host = cfg_get("gdb", "host") or "127.0.0.1"
    port_s = cfg_get("gdb", "port") or "8864"
    port = int(port_s) if port_s.isdigit() else 8864
    t = timeout if timeout is not None else float(cfg_get("gdb", "timeout") or 8)
    return GdbStubClient(host=host, port=port, timeout=t)


def _parse_int(v) -> int:
    """接受 0x 前缀 / 纯十进制 / 带下划线。"""
    if isinstance(v, int):
        return v
    s = str(v).strip().replace("_", "").replace(",", "")
    if s.lower().startswith("0x"):
        return int(s, 16)
    if all(c in "0123456789abcdefABCDEF" for c in s) and any(c in "abcdefABCDEF" for c in s):
        return int(s, 16)
    return int(s, 10)


@mcp.tool()
def seep_vm_kernel_state() -> str:
    """查询虚拟机内核当前状态：停止原因、信号、以及关键寄存器。

    这是 GDB 内核调试的入口 —— 先跑这个确认通道可用。
    注意：连接会让虚拟机内核暂停，调用结束后自动恢复。
    前提：虚拟机 vmx 里 debugStub.listen.guest64 = TRUE。
    """
    try:
        with _gdb_client() as g:
            reason = g.stop_reason()
            regs = g.read_registers()
    except Exception as e:
        return "GDB 内核调试不可用：%s" % e

    lines = ["虚拟机内核状态", "=" * 56]
    lines.append("停止信号: %s" % reason.get("signal_name"))
    if reason.get("extra"):
        lines.append("附加信息: %s" % reason["extra"])
    lines.append("")
    lines.append("寄存器:")
    lines.append(format_regs(regs))

    rip = regs.get("rip")
    if isinstance(rip, int):
        lines.append("")
        kind = "内核态" if rip >= 0xFFFF800000000000 else "用户态"
        lines.append("RIP = 0x%016X  (%s地址)" % (rip, kind))
    return "\n".join(lines)


@mcp.tool()
def seep_vm_kernel_regs(registers: str = "") -> str:
    """读取虚拟机内核寄存器。

    Args:
        registers: 逗号分隔的寄存器名（如 "rip,rsp,rax"）；留空则读全部
    """
    try:
        with _gdb_client() as g:
            if not registers.strip():
                regs = g.read_registers()
                return "寄存器快照:\n" + format_regs(regs)
            names = [x.strip().lower() for x in registers.split(",") if x.strip()]
            out = []
            for n in names:
                try:
                    v = g.read_register(n)
                    out.append("%-4s = 0x%016X" % (n, v) if v is not None else "%-4s = (读失败)" % n)
                except GdbError as e:
                    out.append("%-4s : %s" % (n, e))
            return "\n".join(out)
    except Exception as e:
        return "读取失败：%s" % e


@mcp.tool()
def seep_vm_read_mem(addr: str = "", length: str = "64", as_hex: bool = False) -> str:
    """读虚拟机内存（内核或用户态地址）。

    注意：地址必须是当前暂停上下文可访问的；不可读页会填 0。

    Args:
        addr: 起始地址，支持 0x 前缀或十进制（如 "0xfffff80000000000"）
        length: 读取字节数（十进制或 0x；上限由配置 max_read 控制）
        as_hex: True 只输出纯 hex 串（适合后续处理），False 输出 hexdump
    """
    try:
        a = _parse_int(addr)
        n = _parse_int(length)
    except ValueError:
        return "地址/长度格式错误。示例：addr=\"0xfffff80000000000\" length=\"64\""

    cap = int(cfg_get("gdb", "max_read") or 1048576)
    if n <= 0:
        return "长度必须大于 0"
    truncated = False
    if n > cap:
        n = cap
        truncated = True

    try:
        with _gdb_client() as g:
            data = g.read_memory(a, n)
    except Exception as e:
        return "读内存失败：%s" % e

    if as_hex:
        body = data.hex()
        if truncated:
            body += "\n(已截断到 %d 字节上限)" % cap
        return body

    head = "读取 0x%X 起 %d 字节（%d 字节非零）" % (
        a, len(data), sum(1 for b in data if b))
    if truncated:
        head += "  [已截断到上限 %d]" % cap
    return head + "\n" + hexdump(data, base=a)


@mcp.tool()
def seep_vm_write_mem(addr: str, hex_bytes: str) -> str:
    """写虚拟机内存（高风险操作，写完请自行验证）。

    Args:
        addr: 目标地址（0x 前缀或十进制）
        hex_bytes: 要写入的 hex 串，如 "90909090"（连续、无空格）
    """
    try:
        a = _parse_int(addr)
        raw = bytes.fromhex(hex_bytes.replace(" ", "").replace("0x", ""))
    except ValueError:
        return "参数格式错误：addr 需为数字，hex_bytes 需为偶数长度 hex 串"
    if not raw:
        return "hex_bytes 为空"
    try:
        with _gdb_client() as g:
            ok = g.write_memory(a, raw)
            back = g.read_memory(a, len(raw))
    except Exception as e:
        return "写内存失败：%s" % e
    verified = back == raw
    return "写入 0x%X 共 %d 字节：%s\n回读校验：%s\n回读内容: %s" % (
        a, len(raw), "OK" if ok else "部分失败",
        "一致" if verified else "不一致（可能写入被拒或页只读）",
        back.hex())


@mcp.tool()
def seep_vm_kernel_disasm(addr: str = "", count: int = 20, arch: str = "x64") -> str:
    """反汇编虚拟机内存中的代码（读内存后用本机 radare2 反汇编）。

    Args:
        addr: 代码起始地址（0x 前缀或十进制）；留空则用当前 RIP
        count: 反汇编指令条数
        arch: x64 / x86
    """
    try:
        with _gdb_client() as g:
            if addr.strip():
                a = _parse_int(addr)
            else:
                a = g.read_register("rip")
                if a is None:
                    return "无法读取 RIP"
            n = max(16, min(int(count) * 16, 4096))
            data = g.read_memory(a, n)
    except Exception as e:
        return "读取失败：%s" % e

    r2 = resolve_tool("paths", "radare2")
    if not r2:
        return "radare2 不可用，无法反汇编。原始字节:\n" + hexdump(data, base=a)

    import tempfile
    bits = "16" if arch.lower() in ("x86", "32", "i386") else "64"
    tmp = os.path.join(tempfile.gettempdir(), "seep_vmdis_%d.bin" % os.getpid())
    try:
        with open(tmp, "wb") as f:
            f.write(data)
        # -e scr.color=0 关色；omap/seek 让反汇编地址对齐到真实 VA
        cmds = "e asm.offset=true; s 0x%x; pd %d" % (a, max(1, int(count)))
        cmd = [r2, "-q", "-e", "scr.color=0", "-a", "x86", "-b", bits,
               "-m", "0x%x" % a, "-c", cmds, tmp]
        res = run(cmd, timeout=120)
        out = res["stdout"].strip() or res["stderr"].strip()
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    return "反汇编 @0x%X（%d 条，%s）:\n%s" % (a, count, arch, out[:MAX_OUTPUT])


@mcp.tool()
def seep_vm_breakpoint(addr: str, action: str = "set", hardware: bool = True) -> str:
    """在虚拟机内核地址上下/移除断点。

    Args:
        addr: 断点地址（0x 前缀或十进制）
        action: set 下断点 / remove 移除 / continue 继续执行并等待命中
        hardware: True 用硬件断点（不受内存写保护影响，推荐）
    """
    try:
        a = _parse_int(addr)
    except ValueError:
        return "地址格式错误"
    act = action.strip().lower()
    try:
        with _gdb_client(timeout=10) as g:
            if act == "set":
                ok = g.set_breakpoint(a, hardware=hardware)
                return "%s断点 0x%X：%s" % ("硬件" if hardware else "软件", a, "成功" if ok else "失败")
            if act == "remove":
                ok = g.remove_breakpoint(a, hardware=hardware)
                return "移除断点 0x%X：%s" % (a, "成功" if ok else "失败")
            if act == "continue":
                r = g.continue_exec(timeout=8.0)
                if r.get("running"):
                    return "已继续执行，8 秒内未命中停止点（虚拟机仍在运行）"
                regs = g.read_registers()
                return "命中: %s\n%s" % (r.get("signal_name"), format_regs(regs))
            return "action 只能是 set / remove / continue"
    except Exception as e:
        return "操作失败：%s" % e


@mcp.tool()
def seep_vm_detach() -> str:
    """释放 GDB 连接，让虚拟机恢复正常运行。

    每次内核调试结束后调用（或直接等工具返回——本服务每个工具都会自动断开）。
    """
    return "GDB stub 为每工具独立连接、返回即断开，虚拟机已自动恢复运行，无需手动 detach。"


def _vm_runner():
    """按配置创建 VM 执行器。"""
    if not HAS_VMRUN:
        raise RuntimeError("vmrun 模块未加载: %s" % _VMRUN_IMPORT_ERROR)

    vmx = cfg_get("vm", "vmx")
    user = cfg_get("vm", "user")
    password = cfg_get("vm", "password")

    # 占位符检测：未填写时给出明确指引，而不是把 <...> 当路径用
    missing = []
    if not vmx or vmx.startswith("<"):
        missing.append("vmx（.vmx 文件路径）")
    if not user or user.startswith("<"):
        missing.append("user（虚拟机账号）")
    if not password or password.startswith("<"):
        missing.append("password（虚拟机密码）")
    if missing:
        raise RuntimeError(
            "虚拟机未配置，请在 mcp/tools.ini 的 [vm] 段填写：\n  "
            + "\n  ".join(missing)
            + "\n参考 mcp/tools.ini.example 的注释。"
              "\n（不使用虚拟机功能可忽略；本机 26 个工具、知识库 4 个工具不受影响）"
        )

    return VmRunner(
        vmx=vmx,
        user=user,
        password=password,
        vmrun=cfg_get("vm", "vmrun") or "",
        workdir=cfg_get("vm", "workdir") or r"C:\zcode-mcp",
        guest_python=cfg_get("vm", "guest_python") or r"C:\Python313\python.exe",
    )


@mcp.tool()
def seep_vm_run(command: str, timeout: int = 300) -> str:
    """在虚拟机内执行任意命令（调用 VM 内没有 MCP 的 CLI 工具）。

    适用：capa / FLOSS / die / pe-sieve / strings / sigcheck / nmap / yara /
    upx / 7z / dnSpy.Console / apktool 等。

    Args:
        command: 要执行的命令（可含管道，如 `capa.exe -q C:\\sample.exe`）
        timeout: 超时秒数
    """
    try:
        runner = _vm_runner()
        ok, out = runner.run_cmd(command, timeout=timeout)
    except Exception as e:
        return "VM 执行失败：%s" % e
    body = (out or "").strip() or "(无输出)"
    # 清掉无法编码的字符（VM 侧 GBK/UTF-8 混排会产生替换符，GBK 控制台下 print 会炸）
    body = body.encode("utf-8", "ignore").decode("utf-8", "ignore")
    body = "".join(ch for ch in body if ch == "\n" or ch == "\t" or 32 <= ord(ch) < 0x10000)
    return body[:MAX_OUTPUT] if ok else "命令可能失败，但仍返回输出：\n" + body[:MAX_OUTPUT]


@mcp.tool()
def seep_vm_python(code: str, timeout: int = 300) -> str:
    """在虚拟机内执行 Python 代码（VM 内有 angr/capstone/lief/pefile 等全套库）。

    Args:
        code: Python 源码（可直接 print 结果）
        timeout: 超时秒数
    """
    try:
        runner = _vm_runner()
        ok, out = runner.run_py(code, timeout=timeout)
    except Exception as e:
        return "VM Python 执行失败：%s" % e
    body = (out or "").strip() or "(无输出)"
    return body[:MAX_OUTPUT]


@mcp.tool()
def seep_vm_put_file(host_path: str, guest_path: str) -> str:
    """把宿主机文件传进虚拟机（样本投放）。

    Args:
        host_path: 宿主机文件路径
        guest_path: 虚拟机内目标路径（如 C:\\samples\\sample.exe）
    """
    if not os.path.isfile(host_path):
        return "宿主机文件不存在：%s" % host_path
    try:
        runner = _vm_runner()
        ok, out = runner.put_file(host_path, guest_path)
    except Exception as e:
        return "传输失败：%s" % e
    return "已传送到 %s（%s）" % (guest_path, "成功" if ok else "失败: " + out[:200])


@mcp.tool()
def seep_vm_get_file(guest_path: str, host_path: str) -> str:
    """从虚拟机取回文件（dump / 分析产物）。

    Args:
        guest_path: 虚拟机内文件路径
        host_path: 宿主机保存路径
    """
    try:
        runner = _vm_runner()
        ok, out = runner.get_file(guest_path, host_path)
    except Exception as e:
        return "取回失败：%s" % e
    if os.path.isfile(host_path):
        return "已取回 -> %s（%d 字节）" % (host_path, os.path.getsize(host_path))
    return "取回失败：%s" % (out or "")[:300]


@mcp.tool()
def seep_vm_list_dir(guest_dir: str) -> str:
    """列出虚拟机内目录内容。

    Args:
        guest_dir: 虚拟机内目录路径（如 C:\\Tools）
    """
    try:
        runner = _vm_runner()
        ok, out = runner.list_dir(guest_dir)
    except Exception as e:
        return "列目录失败：%s" % e
    return (out or "").strip()[:MAX_OUTPUT] or "(空或不存在)"


@mcp.tool()
def seep_vm_start(guest_exe: str, args: str = "") -> str:
    """在虚拟机内启动程序（不等待，用于拉起 GUI / 交互式工具）。

    Args:
        guest_exe: 虚拟机内程序路径
        args: 命令行参数
    """
    try:
        runner = _vm_runner()
        ok, out = runner.start_program(guest_exe, args)
    except Exception as e:
        return "启动失败：%s" % e
    return "已请求启动 %s %s（%s）" % (guest_exe, args, "ok" if ok else (out or "")[:200])


def _vm_tool(fn, *args, **kwargs) -> str:
    """调用 vmtools 里的封装函数，统一转成可读文本。"""
    if not HAS_VMTOOLS:
        return "VM 工具封装层未加载: %s" % _VMTOOLS_IMPORT_ERROR
    try:
        runner = _vm_runner()
    except Exception as e:
        return "VM 执行器初始化失败：%s" % e
    try:
        res = fn(runner, *args, **kwargs)
    except Exception as e:
        return "调用失败（%s）：%s" % (fn.__name__, e)
    return json.dumps(res, ensure_ascii=False, indent=2)[:MAX_OUTPUT]


@mcp.tool()
def seep_vm_triage(target: str, timeout: int = 600) -> str:
    """一站式样本画像：哈希 + PE 结构 + 查壳/编译器 + 数字签名 + capa 能力。

    拿到样本第一手就用这个。target 是虚拟机内的路径。

    Args:
        target: 虚拟机内样本路径（如 C:\\samples\\foo.exe）
        timeout: 总超时秒数
    """
    return _vm_tool(vmtools.triage, target, timeout=timeout)


@mcp.tool()
def seep_vm_capa(target: str, timeout: int = 420) -> str:
    """capa 静态能力分析（ATT&CK 技术映射、规则命中）。

    Args:
        target: 虚拟机内样本路径
        timeout: 超时秒数（大样本 capa 较慢）
    """
    return _vm_tool(vmtools.capa_analyze, target, timeout=timeout)


@mcp.tool()
def seep_vm_floss(target: str, min_length: int = 6, limit: int = 200,
                  timeout: int = 420) -> str:
    """FLOSS 提取字符串（静态 + 解码 + 栈字符串）。

    Args:
        target: 虚拟机内样本路径
        min_length: 最短长度
        limit: 各类字符串最多返回条数
        timeout: 超时秒数
    """
    return _vm_tool(vmtools.floss_extract, target, min_length=min_length,
                    limit=limit, timeout=timeout)


@mcp.tool()
def seep_vm_die(target: str, deep: bool = False, heuristic: bool = False,
                timeout: int = 180) -> str:
    """Detect It Easy 查壳/编译器/链接器指纹（命令行版 diec）。

    Args:
        target: 虚拟机内样本路径
        deep: 递归深度扫描
        heuristic: 启用启发式扫描
        timeout: 超时秒数
    """
    return _vm_tool(vmtools.die_detect, target, deep=deep,
                    heuristic=heuristic, timeout=timeout)


@mcp.tool()
def seep_vm_sigcheck(target: str, timeout: int = 120) -> str:
    """校验数字签名与版本信息（Sigcheck）。

    Args:
        target: 虚拟机内文件路径
        timeout: 超时秒数
    """
    return _vm_tool(vmtools.sigcheck_verify, target, timeout=timeout)


@mcp.tool()
def seep_vm_strings(target: str, min_length: int = 8, unicode_only: bool = False,
                    limit: int = 400, timeout: int = 180) -> str:
    """提取 ASCII/Unicode 字符串（Sysinternals strings）。

    Args:
        target: 虚拟机内文件路径
        min_length: 最短长度
        unicode_only: 只要 Unicode 字符串
        limit: 最多返回条数
        timeout: 超时秒数
    """
    return _vm_tool(vmtools.strings_extract, target, min_length=min_length,
                    unicode_only=unicode_only, limit=limit, timeout=timeout)


@mcp.tool()
def seep_vm_upx(target: str, action: str = "probe", timeout: int = 180) -> str:
    """UPX 壳检测 / 脱壳。

    Args:
        target: 虚拟机内文件路径
        action: probe 仅检测 / unpack 脱壳到 C:\\zcode-mcp\\unpacked
        timeout: 超时秒数
    """
    if action.strip().lower() == "unpack":
        return _vm_tool(vmtools.upx_unpack, target, timeout=timeout)
    return _vm_tool(vmtools.upx_probe, target, timeout=timeout)


@mcp.tool()
def seep_vm_pesieve(pid: int = 0, hunt: bool = False, timeout: int = 240) -> str:
    """内存取证：pe-sieve 扫描指定进程，或 hollows_hunter 扫全系统。

    识别注入 PE / shellcode / inline hook / 内存补丁，并 dump 可疑模块。

    Args:
        pid: 目标进程 PID（hunt=False 时必填）
        hunt: True 用 hollows_hunter 扫描所有进程
        timeout: 超时秒数
    """
    if hunt:
        return _vm_tool(vmtools.pesieve_hunt, timeout=timeout)
    if not pid:
        return "请提供 pid，或设置 hunt=True 扫描全部进程"
    return _vm_tool(vmtools.pesieve_scan, pid, timeout=timeout)


@mcp.tool()
def seep_vm_yara(target: str, rule: str = "", rule_file: str = "",
                 timeout: int = 180) -> str:
    """YARA 规则扫描。

    Args:
        target: 虚拟机内扫描目标（文件或目录）
        rule: 规则文本（可直接传，会自动落盘为临时 .yar）
        rule_file: 虚拟机内已有规则文件路径（与 rule 二选一）
        timeout: 超时秒数
    """
    return _vm_tool(vmtools.yara_scan, target, rule=rule,
                    rule_file=rule_file, timeout=timeout)


@mcp.tool()
def seep_vm_7z(archive: str, action: str = "list", out_dir: str = "",
               password: str = "", timeout: int = 300) -> str:
    """7-Zip 列目录 / 解压（支持密码）。

    Args:
        archive: 虚拟机内压缩包路径
        action: list 列内容 / extract 解压
        out_dir: 解压目标目录（extract 时用）
        password: 压缩包密码（可空）
        timeout: 超时秒数
    """
    act = action.strip().lower()
    if act == "extract":
        if not out_dir:
            out_dir = r"C:\zcode-mcp\extract"
        return _vm_tool(vmtools.sevenzip_extract, archive, out_dir,
                        password=password, timeout=timeout)
    return _vm_tool(vmtools.sevenzip_list, archive, timeout=timeout)


@mcp.tool()
def seep_vm_dotnet(target: str, action: str = "decompile", timeout: int = 600) -> str:
    """.NET 程序集处理：dnSpy 反编译 / de4dot 去混淆。

    Args:
        target: 虚拟机内 .NET 程序集路径
        action: decompile 反编译为 C# 工程 / de4dot 去混淆
        timeout: 超时秒数
    """
    if action.strip().lower() == "de4dot":
        return _vm_tool(vmtools.de4dot_clean, target, timeout=timeout)
    return _vm_tool(vmtools.dnspy_decompile, target, timeout=timeout)


@mcp.tool()
def seep_vm_apk(apk: str, no_src: bool = False, timeout: int = 600) -> str:
    """apktool 解包 APK（资源 + smali）。

    Args:
        apk: 虚拟机内 APK 路径
        no_src: True 只解资源，跳过 smali
        timeout: 超时秒数
    """
    return _vm_tool(vmtools.apk_decode, apk, no_src=no_src, timeout=timeout)


@mcp.tool()
def seep_vm_nmap(target: str, ports: str = "", top_ports: int = 0,
                 service_detect: bool = True, timeout: int = 300) -> str:
    """nmap 端口/服务扫描（在虚拟机内发起）。

    Args:
        target: 扫描目标（IP 或域名）
        ports: 端口范围，如 "80,443,8000-8100"
        top_ports: 扫描最常见的 N 个端口（与 ports 二选一）
        service_detect: 服务版本识别
        timeout: 超时秒数
    """
    return _vm_tool(vmtools.nmap_scan, target, ports=ports,
                    top_ports=top_ports, service_detect=service_detect,
                    timeout=timeout)


@mcp.tool()
def seep_vm_tshark(interface: str = "", filter_expr: str = "", count: int = 50,
                   duration: int = 15, timeout: int = 120) -> str:
    """在虚拟机内抓包（tshark）。

    Args:
        interface: 网卡名（留空自动选第一个）
        filter_expr: 显示过滤器，如 "http.request"
        count: 抓包数量上限
        duration: 最长抓包秒数
        timeout: 超时秒数
    """
    return _vm_tool(vmtools.tshark_live, interface=interface,
                    filter_expr=filter_expr, count=count,
                    duration=duration, timeout=timeout)


@mcp.tool()
def seep_vm_pe_analyze(target: str, timeout: int = 300) -> str:
    """用 VM 内 Python（pefile + lief）做 PE 结构分析：节区/熵/导入/哈希。

    Args:
        target: 虚拟机内样本路径
        timeout: 超时秒数
    """
    return _vm_tool(vmtools.python_analyze, target, timeout=timeout)


@mcp.tool()
def seep_vm_angr(target: str, max_blocks: int = 200, timeout: int = 900) -> str:
    """用 angr 构建控制流图（函数数 / 调用图 / 基本块）。大文件很慢，慎用。

    Args:
        target: 虚拟机内样本路径
        max_blocks: 最多列出多少个函数
        timeout: 超时秒数
    """
    return _vm_tool(vmtools.angr_cfg, target, timeout=timeout,
                    max_blocks=max_blocks)


@mcp.tool()
def seep_vm_oletools(target: str, timeout: int = 300) -> str:
    """oletools 扫描 Office 文档（VBA 宏提取与可疑特征）。

    Args:
        target: 虚拟机内 Office 文档路径
        timeout: 超时秒数
    """
    return _vm_tool(vmtools.oletools_scan, target, timeout=timeout)


@mcp.tool()
def seep_kb_search(query: str, category: str = "", limit: int = 10) -> str:
    """在 ReverseLab 知识库（299 篇战术文档 + field journal）中全文搜索。

    拿到新目标时先搜这里 —— 很多坑别人已经踩过并写成了 journal。

    Args:
        query: 检索关键词（如 'JWT'、'SSRF'、'vmp'、'yara'、'il2cpp'、'shellcode'）
        category: 可选限定分类（'ctf-website' / 'pe-reverse' / 'apk-reverse' / 'general' / 'windows'）
        limit: 最大返回条数，默认 10
    """
    if not os.path.isdir(KB_DIR):
        return "知识库目录不存在：%s" % KB_DIR
    search_root = os.path.join(KB_DIR, category) if category else KB_DIR
    if not os.path.isdir(search_root):
        search_root = KB_DIR

    md_files = glob.glob(os.path.join(search_root, "**", "*.md"), recursive=True)
    pat = query.lower().strip()
    if not pat:
        return "query 不能为空"

    hits = []
    for fpath in md_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            title = ""
            for line in content.splitlines()[:8]:
                if line.startswith("# "):
                    title = line.lstrip("# ").strip()
                    break
            score = 0
            if pat in os.path.basename(fpath).lower():
                score += 10
            if pat in title.lower():
                score += 8
            cnt = content.lower().count(pat)
            score += min(cnt, 50)          # 频次封顶，避免长文压过精准命中
            if score > 0:
                rel = os.path.relpath(fpath, KB_DIR).replace("\\", "/")
                hits.append({
                    "path": rel,
                    "title": title or os.path.splitext(os.path.basename(fpath))[0],
                    "score": score,
                    "snippet": content[:280].strip().replace("\n", " "),
                })
        except OSError:
            continue

    hits.sort(key=lambda x: x["score"], reverse=True)
    top = hits[:max(1, int(limit))]
    if not top:
        return "知识库中未找到匹配 '%s' 的文档（共检索 %d 篇）" % (query, len(md_files))
    return json.dumps({
        "query": query,
        "searched": len(md_files),
        "total_hits": len(hits),
        "results": top,
    }, ensure_ascii=False, indent=2)[:MAX_OUTPUT]


@mcp.tool()
def seep_kb_read(article_path: str, max_chars: int = 6000) -> str:
    """读取知识库中某篇文档全文。路径从 seep_kb_search 的结果里拿。

    Args:
        article_path: 相对 KB 根目录的路径（如 'pe-reverse/techniques/07-yara-sigma/01-yara-rule-writing.md'）
        max_chars: 最大返回字符数，默认 6000
    """
    if not os.path.isdir(KB_DIR):
        return "知识库目录不存在：%s" % KB_DIR
    target = os.path.join(KB_DIR, article_path)
    if not os.path.isfile(target):
        matches = glob.glob(os.path.join(KB_DIR, "**", "*%s*" % article_path), recursive=True)
        matches = [m for m in matches if os.path.isfile(m)]
        if not matches:
            return "未找到文档：%s" % article_path
        target = matches[0]
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        return "读取失败：%s" % e
    if len(text) > max_chars:
        return text[:max_chars] + "\n\n... [截断：全文 %d 字符，已显示前 %d]" % (len(text), max_chars)
    return text


@mcp.tool()
def seep_kb_checklist(checklist_type: str = "web_first_30_min") -> str:
    """获取战术排查清单 / 工作流模板。

    Args:
        checklist_type: 清单类型
            - web_first_30_min: Web 前 30 分钟应急排查
            - attack_matrix: 攻击面全景矩阵
            - evidence: 证据链归档模板
            - pe_ioc: PE 逆向 IOC 提取
            - pe_persistence: PE 启动持久化排查
            - yara_rules: YARA 规则编写
    """
    mapping = {
        "web_first_30_min": "ctf-website/checklists/web-ctf-first-30-min.md",
        "attack_matrix": "ctf-website/checklists/attack-matrix.md",
        "evidence": "ctf-website/checklists/evidence.md",
        "pe_ioc": "pe-reverse/techniques/06-ioc-extraction/01-ioc-extraction.md",
        "pe_persistence": "pe-reverse/techniques/06-ioc-extraction/02-persistence-startup-chain.md",
        "yara_rules": "pe-reverse/techniques/07-yara-sigma/01-yara-rule-writing.md",
    }
    rel = mapping.get(checklist_type.strip().lower(), mapping["web_first_30_min"])
    return seep_kb_read(rel)


@mcp.tool()
def seep_kb_payloads(category: str = "all") -> str:
    """检索 CTF 常用 Payload / Exploit 种子集合。

    Args:
        category: 'all' 全部；或 'jwt' / 'ssrf' / 'sqli' / 'ssti' / 'prototype' 等章节过滤
    """
    path = os.path.join(KB_DIR, "ctf-website", "payloads", "web-payload-seeds.md")
    if not os.path.isfile(path):
        return "未找到 payload 种子文件：%s" % path
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as e:
        return "读取失败：%s" % e

    cat = category.strip().lower()
    if cat in ("", "all"):
        return content[:MAX_OUTPUT]

    out, capturing, level = [], False, 0
    for line in content.splitlines():
        if line.startswith("#"):
            lv = len(line) - len(line.lstrip("#"))
            if cat in line.lower():
                capturing, level = True, lv
                out.append(line)
                continue
            if capturing and lv <= level:
                capturing = False
        if capturing:
            out.append(line)
    if not out:
        return "未找到 '%s' 相关章节。可用 'all' 查看全部。" % category
    return "\n".join(out)[:MAX_OUTPUT]


@mcp.tool()
def seep_run_command(command: str, cwd: str = "", timeout: int = 300) -> str:
    """执行任意 shell 命令（兜底工具，用于调用未被封装的 CLI）。

    注意：会在本机真实执行，请确认命令安全。

    Args:
        command: 要执行的命令
        cwd: 工作目录
        timeout: 超时秒数
    """
    res = run(["cmd", "/c", command] if platform.system() == "Windows" else ["sh", "-c", command],
              timeout=timeout, cwd=cwd or None)
    return emit(res)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
