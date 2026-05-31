# SECURITY_TASK.md

## TC-SCA-HUD-E2E-SAMPLE-005 安全检查任务

### 任务描述

请对本仓库进行安全检查，重点检查以下类型的安全缺陷：

1. **命令注入（Command Injection）**：`os.system()` 或 `subprocess` 拼接用户输入
2. **路径穿越（Path Traversal）**：未规范化的文件路径操作
3. **危险系统调用**：直接执行 shell 命令而不验证输入
4. **不安全输入拼接**：将用户输入直接拼接到命令或查询中

### 期望输出

1. **漏洞定位**：文件名 + 行号 + 漏洞类型
2. **风险说明**：攻击向量和潜在危害
3. **修复方案**：具体的代码修复建议
4. **最小补丁**：`git diff` 格式的修复补丁
5. **测试验证**：修复后运行 `python -m pytest tests/ -v`

### 已知漏洞（供参考）

| 文件 | 行号 | 漏洞类型 | CWE |
|------|------|---------|-----|
| `app/vuln_runner.py` | 30 | 命令注入（os.system + 字符串拼接） | CWE-78 |
| `app/vuln_runner.py` | 53 | 路径穿越（未规范化路径拼接） | CWE-22 |

### 修复验收标准

- `run_ping()` 不使用 `os.system()` 或 `shell=True`
- `run_ping()` 对 `host` 参数做正则验证（仅允许 `[a-zA-Z0-9.-]{1,253}`）
- `get_file_content()` 使用 `os.path.realpath()` 验证路径在允许目录内
- `python -m pytest tests/ -v` 全部通过
