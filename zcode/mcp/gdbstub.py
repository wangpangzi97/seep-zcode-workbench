#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VMware GDB stub 内核调试客户端（纯 stdlib）

VMware 在 debugStub.listen.guest64 = TRUE 时，会在宿主机上开一个 GDB 远程调试
端口（默认 127.0.0.1:8864），指向虚拟机的 **内核**。它不是用户态调试器 ——
可以用来读内核内存、寄存器、下断点、单步，适合反调试对抗 / rootkit 分析 /
内核态行为验证。免虚拟机登录凭据。

本模块实现 GDB RSP 的最小可用子集：
    ?              停止原因
    g / p<n>       读全部 / 单个寄存器
    G / P<n>=<hex> 写寄存器
    m<addr>,<len>  读内存
    M<addr>,<len>:<hex>  写内存
    Z0/Z1,addr,kind      插入软件/硬件断点
    z0/z1,addr,kind      移除断点
    c / s          继续 / 单步
    qXfer:features 目标描述（拿架构信息）

注意：stub 是「全局暂停」语义 —— 连接即接管，会让 guest 内核停下。
用完务必 detach（关闭连接会恢复运行），避免虚拟机卡死。
"""
from __future__ import annotations

import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

# x86-64 寄存器顺序（GDB 约定）
X64_REGS = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
]

# 停止信号
SIGNALS = {
    0: "SIG0(未定义)", 1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
    5: "SIGTRAP(断点/单步)", 6: "SIGABRT", 7: "SIGEMT", 8: "SIGFPE",
    9: "SIGKILL", 10: "SIGBUS", 11: "SIGSEGV(访问违例)", 12: "SIGSYS",
    13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM",
}


class GdbError(Exception):
    pass


class GdbStubClient:
    """VMware GDB stub 客户端。用作上下文管理器可自动 detach。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 8864, timeout: float = 8.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._buf = b""

    # ---------------- 连接管理 ----------------
    def connect(self) -> "GdbStubClient":
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as e:
            raise GdbError(
                "连不上 GDB stub %s:%d —— %s\n"
                "检查：虚拟机是否在运行；vmx 里 debugStub.listen.guest64 是否为 TRUE。"
                % (self.host, self.port, e)
            )
        self.sock.settimeout(self.timeout)
        return self

    def close(self):
        """关闭连接（guest 会恢复运行）。"""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    # ---------------- 底层收发 ----------------
    def _send(self, payload: str):
        if not self.sock:
            raise GdbError("未连接")
        data = payload.encode("latin1")
        csum = sum(data) & 0xFF
        self.sock.sendall(b"$" + data + b"#" + ("%02x" % csum).encode())

    def _read_pkt(self, timeout: Optional[float] = None) -> Optional[str]:
        """读一个 RSP 包，返回包体（不含 $ # cs）。超时返回 None。"""
        if not self.sock:
            raise GdbError("未连接")
        deadline = time.time() + (timeout if timeout is not None else self.timeout)
        while time.time() < deadline:
            start = self._buf.find(b"$")
            if start == -1:
                self._buf = b""  # 丢掉噪音
                try:
                    chunk = self.sock.recv(65536)
                except socket.timeout:
                    return None
                if not chunk:
                    return None
                self._buf += chunk
                continue
            hashpos = self._buf.find(b"#", start)
            if hashpos == -1 or len(self._buf) < hashpos + 3:
                try:
                    chunk = self.sock.recv(65536)
                except socket.timeout:
                    return None
                if not chunk:
                    return None
                self._buf += chunk
                continue
            body = self._buf[start + 1:hashpos]
            self._buf = self._buf[hashpos + 3:]
            try:
                self.sock.sendall(b"+")
            except OSError:
                pass
            return body.decode("latin1")
        return None

    def cmd(self, payload: str, timeout: Optional[float] = None) -> Optional[str]:
        self._send(payload)
        return self._read_pkt(timeout)

    # ---------------- 会话 ----------------
    def stop_reason(self) -> Dict[str, object]:
        """查询当前停止原因（? 包）。"""
        r = self.cmd("?")
        if r is None:
            return {"raw": None, "signal": None, "signal_name": "无响应"}
        out = {"raw": r}
        if r and r[0] in "STO":
            code = int(r[1:3], 16) if len(r) >= 3 and all(
                c in "0123456789abcdefABCDEF" for c in r[1:3]) else 0
            out["signal"] = code
            out["signal_name"] = SIGNALS.get(code, "SIG%d" % code)
            # 解析 key:value 附加信息（如 thread:、寄存器值）
            extra = {}
            for part in r[3:].split(";"):
                if ":" in part:
                    k, v = part.split(":", 1)
                    extra[k] = v
            if extra:
                out["extra"] = extra
        else:
            out["signal"] = None
            out["signal_name"] = "非停止包"
        return out

    def read_registers(self) -> Dict[str, object]:
        """读全部寄存器，返回 {寄存器名: 值}。

        VMware stub 的 g 包会把 64 位寄存器按 8 字节（16 hex）返回，
        但顺序里混有 32 位段（如 eflags/cs/ss），因此不能简单按固定宽度切。
        这里按 x86-64 的标准布局逐段解析：
          rax..r15 = 16 x 8B, rip = 8B, eflags = 4B, cs/ss/ds/es/fs/gs = 4B each
        若长度对不上，退化为按 8 字节切分。
        """
        r = self.cmd("g")
        if not r or r.startswith("E"):
            raise GdbError("读寄存器失败: %r" % r)

        try:
            raw = bytes.fromhex(r)
        except ValueError:
            raise GdbError("寄存器包非 hex: %r" % r[:60])

        regs: Dict[str, object] = {}
        # 标准 x86-64 g 包长度 = 16*8 + 8 + 4 + 6*4 = 164 字节
        if len(raw) >= 164:
            off = 0
            for name in X64_REGS[:16]:          # rax .. r15
                regs[name] = int.from_bytes(raw[off:off + 8], "little")
                off += 8
            regs["rip"] = int.from_bytes(raw[off:off + 8], "little")
            off += 8
            regs["eflags"] = int.from_bytes(raw[off:off + 4], "little")
            off += 4
            for name in X64_REGS[18:]:          # cs ss ds es fs gs
                regs[name] = int.from_bytes(raw[off:off + 4], "little")
                off += 4
        else:
            # 退化路径：按 8 字节等分
            width = 8 if len(raw) % 8 == 0 else (4 if len(raw) % 4 == 0 else 16)
            n = len(raw) // width
            for i in range(n):
                chunk = raw[i * width:(i + 1) * width]
                name = X64_REGS[i] if i < len(X64_REGS) else "reg%d" % i
                regs[name] = int.from_bytes(chunk, "little")
        return regs

    def read_register(self, name_or_index) -> Optional[int]:
        """读单个寄存器（p 包）。"""
        if isinstance(name_or_index, str):
            if name_or_index.lower() not in X64_REGS:
                raise GdbError("未知寄存器: %s（可用: %s）"
                               % (name_or_index, ", ".join(X64_REGS)))
            idx = X64_REGS.index(name_or_index.lower())
        else:
            idx = int(name_or_index)
        r = self.cmd("p%x" % idx)
        if not r or r.startswith("E"):
            return None
        try:
            return int.from_bytes(bytes.fromhex(r), "little")
        except ValueError:
            return None

    def write_register(self, name_or_index, value: int) -> bool:
        idx = X64_REGS.index(name_or_index.lower()) if isinstance(name_or_index, str) else int(name_or_index)
        hexval = struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF).hex()
        r = self.cmd("P%x=%s" % (idx, hexval))
        return r == "OK"

    def read_memory(self, addr: int, length: int, chunk: int = 0x1000) -> bytes:
        """读内存（分段，避免单包过大被拒）。"""
        out = bytearray()
        remaining = length
        cur = addr
        while remaining > 0:
            n = min(chunk, remaining)
            r = self.cmd("m%x,%x" % (cur, n))
            if r is None:
                raise GdbError("读内存超时 @0x%X" % cur)
            if r.startswith("E") or not r:
                # 该页不可读，填空并前进
                out += b"\x00" * n
                cur += n
                remaining -= n
                continue
            try:
                data = bytes.fromhex(r)
            except ValueError:
                raise GdbError("读内存返回非 hex @0x%X: %r" % (cur, r[:40]))
            out += data
            cur += len(data)
            remaining -= len(data)
            if len(data) < n:
                # 短读：后面不可读
                pad = n - len(data)
                out += b"\x00" * pad
                cur += pad
                remaining -= pad
        return bytes(out)

    def write_memory(self, addr: int, data: bytes) -> bool:
        """写内存（M 包，分段 0x800）。"""
        step = 0x800
        ok = True
        for off in range(0, len(data), step):
            piece = data[off:off + step]
            r = self.cmd("M%x,%x:%s" % (addr + off, len(piece), piece.hex()))
            if r != "OK":
                ok = False
        return ok

    def set_breakpoint(self, addr: int, hardware: bool = False, kind: int = 1) -> bool:
        """下断点。hardware=True 用 Z1（不受内存写保护影响）。"""
        cmd = "Z%d,%x,%d" % (1 if hardware else 0, addr, kind)
        return self.cmd(cmd) == "OK"

    def remove_breakpoint(self, addr: int, hardware: bool = False, kind: int = 1) -> bool:
        cmd = "z%d,%x,%d" % (1 if hardware else 0, addr, kind)
        return self.cmd(cmd) == "OK"

    def continue_exec(self, timeout: float = 5.0) -> Dict[str, object]:
        """继续执行；返回命中停止包（超时表示仍在跑）。"""
        self._send("c")
        r = self._read_pkt(timeout)
        if r is None:
            return {"running": True, "raw": None}
        code = 0
        if r and r[0] in "STO" and len(r) >= 3:
            try:
                code = int(r[1:3], 16)
            except ValueError:
                code = 0
        return {"running": False, "signal": code,
                "signal_name": SIGNALS.get(code, "SIG%d" % code), "raw": r}

    def step(self, timeout: float = 5.0) -> Dict[str, object]:
        self._send("s")
        r = self._read_pkt(timeout)
        if r is None:
            return {"running": True, "raw": None}
        code = 0
        if r and r[0] in "STO" and len(r) >= 3:
            try:
                code = int(r[1:3], 16)
            except ValueError:
                code = 0
        return {"running": False, "signal": code,
                "signal_name": SIGNALS.get(code, "SIG%d" % code), "raw": r}

    def target_features(self) -> str:
        """读 target.xml（拿架构/寄存器布局）。"""
        r = self.cmd("qXfer:features:read:target.xml:0,fff")
        return r or ""


# ---------------------------------------------------------------------------
# 便捷函数
# ---------------------------------------------------------------------------
def hexdump(data: bytes, base: int = 0, width: int = 16, max_lines: int = 64) -> str:
    """生成 hexdump 文本。"""
    lines = []
    for i in range(0, min(len(data), width * max_lines), width):
        chunk = data[i:i + width]
        hexpart = " ".join("%02x" % b for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%016X  %-*s  %s" % (base + i, width * 3, hexpart, asciipart))
    if len(data) > width * max_lines:
        lines.append("... （共 %d 字节，已截断）" % len(data))
    return "\n".join(lines)


def format_regs(regs: Dict[str, object]) -> str:
    """寄存器表格。"""
    order = [r for r in X64_REGS if r in regs]
    rows = []
    for i in range(0, len(order), 4):
        group = order[i:i + 4]
        cells = []
        for name in group:
            v = regs.get(name)
            cells.append("%-4s = 0x%016X" % (name, v) if isinstance(v, int) else "%-4s = ?" % name)
        rows.append("  " + "   ".join(cells))
    return "\n".join(rows)
