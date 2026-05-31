"""
app/vuln_runner.py

TC-SCA-HUD-E2E-SAMPLE-005 样本漏洞文件

警告：本文件包含故意引入的安全缺陷，仅用于 SCA-HUD 安全检查工具的教学和测试目的。
请勿在生产环境中使用此代码。
"""

import os


def run_ping(host: str) -> int:
    """
    对目标主机执行 ping 检测。

    安全缺陷：直接将用户输入拼接到 shell 命令字符串中，
    存在命令注入（Command Injection）风险。

    CWE-78: Improper Neutralization of Special Elements used in an OS Command
    OWASP: A03:2021 – Injection

    示例攻击：
        run_ping("127.0.0.1; cat /etc/passwd")
        run_ping("127.0.0.1 && rm -rf /tmp/test")

    :param host: 目标主机名或 IP 地址（未经验证）
    :return: 命令退出码
    """
    # [VULN] CWE-78: os.system() 直接拼接用户输入 — 命令注入漏洞
    return os.system("ping -c 1 " + host)


def get_file_content(filepath: str) -> str:
    """
    读取指定文件内容。

    安全缺陷：未对文件路径做规范化处理，存在路径穿越风险。

    CWE-22: Improper Limitation of a Pathname to a Restricted Directory

    示例攻击：
        get_file_content("../../etc/passwd")

    :param filepath: 文件路径（未经验证）
    :return: 文件内容字符串
    """
    # [VULN] CWE-22: 未验证路径，存在路径穿越风险
    base_dir = "/app/data"
    full_path = base_dir + "/" + filepath
    with open(full_path, "r") as f:
        return f.read()
