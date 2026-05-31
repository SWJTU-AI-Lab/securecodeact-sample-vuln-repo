"""
app/vuln_runner.py

TC-SCA-HUD-E2E-SAMPLE-005 安全修复版本

修复说明：
  - run_ping(): 使用 subprocess.run() + 参数列表替代 os.system() 字符串拼接
    - 新增 re.fullmatch() 输入验证，仅允许合法主机名/IP 格式
    - 不使用 shell=True，避免 shell 元字符注入
    - CWE-78 命令注入漏洞已修复
  - get_file_content(): 使用 os.path.realpath() 验证路径在允许目录内
    - 防止路径穿越攻击（../../etc/passwd 等）
    - CWE-22 路径穿越漏洞已修复
"""

import os
import re
import subprocess


def run_ping(host: str) -> int:
    """
    对目标主机执行 ping 检测（安全修复版本）。

    修复：
      1. 使用 re.fullmatch() 验证 host 参数，仅允许 [a-zA-Z0-9.-]{1,253}
      2. 使用 subprocess.run() + 参数列表，不使用 shell=True
      3. 不再使用 os.system() 进行字符串拼接

    :param host: 目标主机名或 IP 地址
    :return: ping 命令退出码（0 表示成功）
    :raises ValueError: 当 host 包含非法字符时
    """
    # [FIX] 输入验证：仅允许合法主机名/IP 格式
    if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
        raise ValueError(f"invalid host: {host!r}")

    # [FIX] 使用参数列表，不使用 shell=True，避免 shell 元字符注入
    result = subprocess.run(
        ["ping", "-c", "1", host],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode


def get_file_content(filepath: str) -> str:
    """
    读取指定文件内容（安全修复版本）。

    修复：
      1. 使用 os.path.realpath() 规范化路径
      2. 验证规范化后的路径必须在 base_dir 内
      3. 防止路径穿越攻击（如 ../../etc/passwd）

    :param filepath: 相对于 base_dir 的文件路径
    :return: 文件内容字符串
    :raises ValueError: 当路径穿越 base_dir 时
    :raises FileNotFoundError: 当文件不存在时
    """
    base_dir = os.path.realpath("/app/data")
    # [FIX] 规范化路径，防止路径穿越
    full_path = os.path.realpath(os.path.join(base_dir, filepath))

    # [FIX] 验证路径必须在 base_dir 内
    if not full_path.startswith(base_dir + os.sep) and full_path != base_dir:
        raise ValueError(f"path traversal detected: {filepath!r}")

    with open(full_path, "r") as f:
        return f.read()
