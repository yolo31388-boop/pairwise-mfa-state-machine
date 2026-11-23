# pairwise-mfa-state-machine

## 领域

安全

## 主题

MFA 状态机

## 说明

半登录态、受限令牌与二次校验时间戳。

初始状态下 `security/mfa_state_machine.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
