#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VMware 虚拟机执行通道（vmrun 封装，纯 stdlib）

用途：把「在虚拟机内跑命令 / 传文件 / 取文件」变成可调用函数，
供 MCP 层封装成工具。这是调用 VM 内**没有 MCP**的 CLI 工具
（capa / FLOSS / die / pe-sieve / strings / sigcheck / nmap / yara ...）的唯一通路。

前提：
  - 虚拟机正在运行
  - VMware Tools 在 guest 内运行（checkToolsState == running）
  - 有 guest 账号密码

关键实测结论（踩过的坑，别改）：
  1. `cmd.exe /c "echo x > file"` 会返回 exit code 1 —— 重定向在 runProgramInGuest
     里的引号处理不可靠。**统一改成：写一个 .py 脚本 >> 让 python 执行**。
  2. `-interactive` 会弹出可见窗口，批量跑时容易和桌面交互冲突；
     纯后台任务不要加。
  3. runProgramInGuest 是**同步**的（不加 -noWait 时），长任务要给足超时。
  4. 结果取回用 copyFileFromGuestToHost，中途 vmrun 偶发失败要重试。
"""
from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile
import time
from typing import Optional, Tuple

DEFAULT_VMRUN_CANDIDATES = [
    r"D:\xuni\vmrun.exe",
    r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
    r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
]


class VmError(Exception):
    pass


def find_vmrun(explicit: str = "") -> str:
    if explicit and os.path.isfile(explicit):
        return explicit
    for c in DEFAULT_VMRUN_CANDIDATES:
        if os.path.isfile(c):
            return c
    found = shutil.which("vmrun")
    if found:
        return found
    raise VmError("找不到 vmrun.exe，请在配置里显式指定路径")


class VmRunner:
    """针对单个 VM 的执行器。"""

    def __init__(self, vmx: str, user: str, password: str,
                 vmrun: str = "", workdir: str = r"C:\zcode-mcp",
                 guest_python: str = r"C:\Python313\python.exe",
                 timeout: int = 300):
        self.vmrun = find_vmrun(vmrun)
        self.vmx = vmx
        self.user = user
        self.password = password
        self.workdir = workdir
        self.guest_python = guest_python
        self.timeout = timeout

    # ---------- 基础 ----------
    def _base(self):
        return [self.vmrun, "-T", "ws", "-gu", self.user, "-gp", self.password]

    def tools_state(self) -> str:
        r = subprocess.run([self.vmrun, "-T", "ws", "checkToolsState", self.vmx],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
        return ((r.stdout or "") + (r.stderr or "")).strip()

    def is_running(self) -> bool:
        r = subprocess.run([self.vmrun, "-T", "ws", "list"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
        return os.path.basename(self.vmx).lower() in (r.stdout or "").lower()

    def _retry(self, args, timeout=None, attempts=3, delay=2.0):
        """带重试的 vmrun 调用（guest 通信偶发失败）。"""
        last = None
        for i in range(attempts):
            try:
                r = subprocess.run(self._base() + args, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace",
                                   timeout=timeout or self.timeout)
                if r.returncode == 0:
                    return True, (r.stdout or "") + (r.stderr or "")
                last = (r.stdout or "") + (r.stderr or "")
                # 认证错误不重试
                if "Invalid user name or password" in last:
                    return False, last
            except subprocess.TimeoutExpired:
                last = "TIMEOUT(%ss)" % (timeout or self.timeout)
            except Exception as e:
                last = str(e)
            time.sleep(delay * (i + 1))
        return False, last or "unknown error"

    # ---------- 执行 ----------
    def run_py(self, code: str, timeout: Optional[int] = None) -> Tuple[bool, str]:
        """在 guest 内执行一段 Python 代码，返回 (ok, stdout+stderr)。

        采用「base64 传脚本 -> python 跑 -> 结果回传」的方式，
        绕开 cmd 重定向在 runProgramInGuest 里的缺陷。
        """
        ok, out = self._run_py_raw(code, timeout)
        return ok, out

    def _run_py_raw(self, code: str, timeout: Optional[int] = None):
        # 每次调用用唯一文件名，避免并发/残留互相覆盖
        import uuid
        tag = uuid.uuid4().hex[:12]
        script_guest = "%s\\__zc_%s.py" % (self.workdir, tag)
        out_guest = "%s\\__zc_%s.out" % (self.workdir, tag)

        b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")
        # 第一步：把脚本写到 guest
        writer = (
            "import base64,pathlib;"
            "pathlib.Path(r'%s').write_bytes(base64.b64decode('%s'));"
            "print('WROTE')" % (script_guest, b64)
        )
        ok, out = self._retry(
            ["runProgramInGuest", self.vmx, self.guest_python, "-c", writer],
            timeout=90, attempts=2)
        if not ok:
            return False, "写入脚本失败: " + out[:400]

        # 第二步：执行，结果写到 guest 侧唯一文件
        runner = (
            "import io,sys,traceback\n"
            "buf=io.StringIO();_so=sys.stdout;sys.stdout=buf\n"
            "try:\n"
            "    exec(compile(open(r'%s','r',encoding='utf-8').read(),'__zc','exec'),"
            "{'__name__':'__main__'})\n"
            "except Exception:\n"
            "    traceback.print_exc(file=buf)\n"
            "finally:\n"
            "    sys.stdout=_so\n"
            "    open(r'%s','w',encoding='utf-8',errors='replace').write(buf.getvalue())\n"
            % (script_guest, out_guest)
        )
        ok, out = self._retry(
            ["runProgramInGuest", self.vmx, self.guest_python, "-c", runner],
            timeout=timeout or self.timeout, attempts=2)

        # 第三步：取回结果
        local = os.path.join(tempfile.gettempdir(), "__zc_%s.txt" % tag)
        if os.path.exists(local):
            os.remove(local)
        ok2, out2 = self._retry(
            ["copyFileFromGuestToHost", self.vmx, out_guest, local],
            timeout=90, attempts=3)
        if os.path.exists(local):
            try:
                data = open(local, "r", encoding="utf-8", errors="replace").read()
            finally:
                try:
                    os.remove(local)
                except OSError:
                    pass
            return True, data
        return False, "取回结果失败: " + (out2 or out)[:400]

    def run_cmd(self, command: str, timeout: Optional[int] = None) -> Tuple[bool, str]:
        """在 guest 内跑一条 shell 命令。

        实现：命令写进 .bat（UTF-8），再用 `cmd /c <bat>` 执行。
        这样引号、管道、重定向都按 cmd 规则解析，且不受 runProgramInGuest
        参数转义的干扰。
        """
        import uuid
        tag = uuid.uuid4().hex[:10]
        bat = "%s\\__zc_%s.bat" % (self.workdir, tag)

        py = (
            "import subprocess, pathlib\n"
            "bat = r'" + bat + "'\n"
            "cmd = " + repr(command) + "\n"
            "pathlib.Path(bat).write_text('@echo off\\r\\n' + cmd + '\\r\\n', encoding='utf-8')\n"
            "p = subprocess.run(['cmd', '/c', bat], capture_output=True, text=True,\n"
            "                   encoding='utf-8', errors='replace')\n"
            "print(p.stdout or '')\n"
            "print(p.stderr or '')\n"
            "print('[exit=%d]' % p.returncode)\n"
        )
        return self.run_py(py, timeout=timeout)

    def put_file(self, host_path: str, guest_path: str) -> Tuple[bool, str]:
        return self._retry(["copyFileFromHostToGuest", self.vmx, host_path, guest_path],
                           timeout=180)

    def get_file(self, guest_path: str, host_path: str) -> Tuple[bool, str]:
        return self._retry(["copyFileFromGuestToHost", self.vmx, guest_path, host_path],
                           timeout=180)

    def list_dir(self, guest_dir: str) -> Tuple[bool, str]:
        py = (
            "import os\n"
            "d = %r\n"
            "try:\n"
            "    for n in sorted(os.listdir(d)):\n"
            "        p = os.path.join(d, n)\n"
            "        print(('DIR  ' if os.path.isdir(p) else 'FILE ') + n)\n"
            "except Exception as e:\n"
            "    print('ERR', e)\n" % guest_dir
        )
        return self.run_py(py)

    def start_program(self, guest_exe: str, args: str = "") -> Tuple[bool, str]:
        """启动 guest 内程序但不等待（用于拉起 GUI/服务）。"""
        cmd = ["runProgramInGuest", self.vmx, "-interactive", "-noWait", guest_exe]
        if args:
            cmd.append(args)
        return self._retry(cmd, timeout=90, attempts=2)
