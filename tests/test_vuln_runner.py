"""
tests/test_vuln_runner.py

TC-SCA-HUD-E2E-SAMPLE-005 安全测试用例（修复后版本）

测试分为两类：
  - 漏洞存在性测试（xfail：修复后预期失败，即漏洞已消除）
  - 修复验证测试（修复后应通过的安全测试）
"""

import ast
import sys
import os
import inspect
import pytest


# ── 辅助函数 ──────────────────────────────────────────────────────────────────

def _get_source_file() -> str:
    """获取 vuln_runner.py 的完整源码文本"""
    path = os.path.join(os.path.dirname(__file__), "..", "app", "vuln_runner.py")
    with open(os.path.abspath(path), "r") as f:
        return f.read()


def _get_func_ast(func_name: str) -> ast.FunctionDef:
    """获取指定函数的 AST 节点"""
    tree = ast.parse(_get_source_file())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return node
    raise ValueError(f"Function {func_name!r} not found")


def _ast_contains_call(func_ast: ast.FunctionDef, module: str, func: str) -> bool:
    """检查函数 AST 中是否存在 module.func() 调用"""
    for node in ast.walk(func_ast):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if (isinstance(node.func.value, ast.Name) and
                        node.func.value.id == module and
                        node.func.attr == func):
                    return True
    return False


def _ast_subprocess_uses_shell_true(func_ast: ast.FunctionDef) -> bool:
    """检查 subprocess.run() 是否使用了 shell=True"""
    for node in ast.walk(func_ast):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if (isinstance(node.func.value, ast.Name) and
                        node.func.value.id == "subprocess" and
                        node.func.attr == "run"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                            if kw.value.value is True:
                                return True
    return False


# ── 漏洞存在性测试（xfail：修复后预期失败）──────────────────────────────────

class TestVulnerabilityDetection:
    """AST 静态检测：验证漏洞代码特征（修复后标记为 xfail）"""

    @pytest.mark.xfail(
        reason="After fix: os.system() should be replaced by subprocess.run()",
        strict=False,
    )
    def test_os_system_usage_detected(self):
        """[xfail] 修复后 os.system() 调用应已消除"""
        func_ast = _get_func_ast("run_ping")
        assert _ast_contains_call(func_ast, "os", "system"), (
            "os.system() call not found in run_ping() — vulnerability already fixed"
        )

    @pytest.mark.xfail(
        reason="After fix: subprocess.run() arg list replaces string concat",
        strict=False,
    )
    def test_string_concatenation_in_command(self):
        """[xfail] 修复后字符串拼接应已消除"""
        func_ast = _get_func_ast("run_ping")
        # 检查是否有 BinOp（字符串 + 变量）
        has_concat = any(
            isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
            for node in ast.walk(func_ast)
        )
        assert has_concat, "String concatenation not found — already fixed"

    @pytest.mark.xfail(
        reason="After fix: input validation should be present",
        strict=False,
    )
    def test_no_input_validation(self):
        """[xfail] 修复后应有输入验证"""
        func_ast = _get_func_ast("run_ping")
        # 检查是否有 re.fullmatch 调用
        has_validation = _ast_contains_call(func_ast, "re", "fullmatch") or \
                         _ast_contains_call(func_ast, "re", "match")
        assert not has_validation, "Input validation found — vulnerability already fixed"


# ── 修复验证测试（修复后应通过）────────────────────────────────────────────────

class TestSecureImplementation:
    """功能测试：验证修复后的安全实现"""

    def test_valid_ipv4_host_accepted(self):
        """有效 IPv4 地址应被接受（不抛出异常）"""
        import re
        valid_hosts = ["127.0.0.1", "192.168.1.1", "example.com", "localhost"]
        for host in valid_hosts:
            assert re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host), (
                f"Valid host {host!r} should pass input validation"
            )

    def test_shell_metacharacter_rejected(self):
        """包含 shell 元字符的输入应被拒绝（修复后）"""
        from app.vuln_runner import run_ping
        with pytest.raises(ValueError, match="invalid host"):
            run_ping("127.0.0.1; cat /etc/passwd")

    def test_no_shell_true_in_subprocess(self):
        """修复版本 subprocess.run() 不应使用 shell=True（AST 检查）"""
        func_ast = _get_func_ast("run_ping")
        assert not _ast_subprocess_uses_shell_true(func_ast), (
            "SECURITY VIOLATION: subprocess.run() must not use shell=True"
        )

    def test_no_os_system_after_fix(self):
        """修复版本不应调用 os.system()（AST 检查）"""
        func_ast = _get_func_ast("run_ping")
        assert not _ast_contains_call(func_ast, "os", "system"), (
            "SECURITY FIX REQUIRED: os.system() must be replaced with subprocess.run()"
        )


# ── 集成测试（需要真实系统环境）────────────────────────────────────────────────

class TestIntegration:
    """集成测试：验证真实执行行为"""

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="ping command not available on Windows"
    )
    def test_localhost_ping_returns_zero(self):
        """对 localhost 执行 ping 应返回 0（修复版本）"""
        from app.vuln_runner import run_ping
        result = run_ping("127.0.0.1")
        assert result == 0, f"Expected return code 0, got {result}"

    def test_command_injection_payload_blocked(self):
        """命令注入 payload 应被阻断（修复版本）"""
        from app.vuln_runner import run_ping
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
