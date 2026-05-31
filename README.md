# securecodeact-sample-vuln-repo

**用途**：TC-SCA-HUD-E2E-SAMPLE-005 端到端测试样本仓库

本仓库包含一个简单、可控、无真实攻击目标的安全缺陷示例，用于验证 SCA-HUD 的安全检查、修复和补丁生成闭环能力。

## 缺陷说明

`app/vuln_runner.py` 中的 `run_ping()` 函数使用 `os.system()` 直接拼接用户输入，存在命令注入风险：

```python
# 漏洞代码
def run_ping(host: str) -> int:
    return os.system("ping -c 1 " + host)
```

攻击者可以通过 `host = "127.0.0.1; rm -rf /"` 等方式注入任意 shell 命令。

## 期望修复

使用 `subprocess.run()` + 参数列表 + 输入验证替代 `os.system()` 字符串拼接。

## 运行测试

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## 文件结构

```
securecodeact-sample-vuln-repo/
├── README.md
├── app/
│   └── vuln_runner.py      # 含命令注入漏洞的示例文件
├── tests/
│   └── test_vuln_runner.py # 安全测试用例
├── requirements.txt
└── SECURITY_TASK.md        # 安全检查任务描述
```
