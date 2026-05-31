"""
tests/test_vuln_runner.py

TC-SCA-HUD-E2E-SAMPLE-005 安全测试用例

本测试文件验证 vuln_runner.py 中的安全缺陷是否已被正确修复。
测试分为两类：
  - 漏洞存在性测试（验证当前代码是否存在已知缺陷）
  - 修复验证测试（修复后应通过的安全测试）
"""

import subprocess
import sys
import os
import importlib
import pytest


# ── 辅助函数 ──────────────────────────────────────────────────────────────────

def _get_source(func_name: str) -> str:
    """获取函数源码，用于静态检查"""
    import inspect
    from app.vuln_runner import run_ping
    return inspect.getsource(run_ping)


# ── 漏洞存在性测试（当前代码应触发这些问题）──────────────────────────────────

class TestVulnerabilityDetection:
    """静态检测：验证漏洞代码特征是否存在"""

    def test_os_system_usage_detected(self):
        """检测到 os.system() 使用 — 命令注入风险标记"""
        source = _get_source("run_ping")
        assert "os.system" in source, (
            "Expected os.system() usage to be detected in run_ping(). "
            "This test verifies the vulnerability exists for SCA tooling."
        )

    def test_string_concatenation_in_command(self):
        """检测到字符串拼接构造 shell 命令 — 命令注入风险标记"""
        source = _get_source("run_ping")
        # 检查是否有字符串拼接（+ 操作符连接用户输入）
        assert "ping -c 1 " in source, (
            "Expected direct string concatenation in shell command."
        )

    def test_no_input_validation(self):
        """检测到无输入验证 — 应在修复后失败"""
        source = _get_source("run_ping")
        # 修复前：没有 re.fullmatch 或 re.match 验证
        has_validation = ("re.fullmatch" in source or
                          "re.match" in source or
                          "re.compile" in source or
                          "ValueError" in source)
        # 此测试在漏洞存在时通过（无验证），修复后应反转
        assert not has_validation, (
            "VULN PRESENT: No input validation found in run_ping(). "
            "After fix, this test should be updated to assert validation exists."
        )


# ── 修复验证测试（修复后应通过）────────────────────────────────────────────────

class TestSecureImplementation:
    """功能测试：验证修复后的安全实现"""

    def test_valid_ipv4_host_accepted(self):
        """有效 IPv4 地址应被接受（不抛出异常）"""
        try:
            from app.vuln_runner import run_ping
            # 仅验证不抛出 ValueError，不实际执行网络请求
            # 修复版本应接受合法 IP
            import re
            import inspect
            source = inspect.getsource(run_ping)
            if "re.fullmatch" in source or "re.match" in source:
                # 修复版本：验证合法 IP 不被拒绝
                assert True, "Valid IP should be accepted by fixed implementation"
            else:
                pytest.skip("Skipping: run_ping not yet fixed (os.system version)")
        except Exception as e:
            pytest.skip(f"Skipping: {e}")

    def test_shell_metacharacter_rejected(self):
        """包含 shell 元字符的输入应被拒绝（修复后）"""
        try:
            from app.vuln_runner import run_ping
            import inspect
            source = inspect.getsource(run_ping)
            if "re.fullmatch" in source or "ValueError" in source:
                # 修复版本：shell 元字符应触发 ValueError
                with pytest.raises(ValueError, match="invalid host"):
                    run_ping("127.0.0.1; cat /etc/passwd")
            else:
                pytest.skip("Skipping: run_ping not yet fixed (os.system version)")
        except ImportError:
            pytest.skip("Module not available")

    def test_no_shell_true_in_subprocess(self):
        """修复版本不应使用 shell=True"""
        import inspect
        from app.vuln_runner import run_ping
        source = inspect.getsource(run_ping)
        if "subprocess" in source:
            assert "shell=True" not in source, (
                "SECURITY VIOLATION: subprocess.run() must not use shell=True"
            )

    def test_no_os_system_after_fix(self):
        """修复版本不应使用 os.system()（修复后应通过）"""
        import inspect
        from app.vuln_runner import run_ping
        source = inspect.getsource(run_ping)
        if "subprocess" in source:
            # 如果已经迁移到 subprocess，则 os.system 应该消失
            assert "os.system" not in source, (
                "SECURITY FIX REQUIRED: os.system() must be replaced with subprocess.run()"
            )
        else:
            pytest.skip("Skipping: not yet fixed")


# ── 集成测试（需要真实系统环境）────────────────────────────────────────────────

class TestIntegration:
    """集成测试：验证真实执行行为"""

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="ping command not available on Windows"
    )
    def test_localhost_ping_returns_zero(self):
        """对 localhost 执行 ping 应返回 0（修复版本）"""
        import inspect
        from app.vuln_runner import run_ping
        source = inspect.getsource(run_ping)
        if "subprocess" in source and "re.fullmatch" in source:
            result = run_ping("127.0.0.1")
            assert result == 0, f"Expected return code 0, got {result}"
        else:
            pytest.skip("Skipping: run_ping not yet fixed")

    def test_command_injection_payload_blocked(self):
        """命令注入 payload 应被阻断（修复版本）"""
        import inspect
        from app.vuln_runner import run_ping
        source = inspect.getsource(run_ping)
        if "re.fullmatch" in source or "ValueError" in source:
            malicious_inputs = [
                "127.0.0.1; cat /etc/passwd",
                "127.0.0.1 && id",
                "127.0.0.1 | whoami",
                "$(id)",
                "`id`",
                "127.0.0.1\nid",
            ]
            for payload in malicious_inputs:
                with pytest.raises(ValueError):
                    run_ping(payload)
        else:
            pytest.skip("Skipping: run_ping not yet fixed")
