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

## 漏洞与修法

**原问题**：MFA 是否通过只取决于会话里的一个布尔字段，客户端篡改响应即可跳过二次验证；
服务端不记录验证时间，也没有越权审计。

**修复后的服务端状态机**（实现见 `security/mfa_state_machine.py`）：

1. **服务端权威状态**：认证状态只存于服务端 `SessionStore`，`session_flag` 读取的是服务端
   状态；客户端声称的布尔值一律忽略，篡改响应无法影响授权。
2. **半登录态（HALF_AUTHENTICATED）**：密码校验通过只建立半登录会话，发放受限令牌
   （5 分钟 TTL、scope=restricted、仅可访问 `/mfa/*` 端点）。
3. **二次校验带时间戳**：MFA 成功后状态迁移为 FULLY_AUTHENTICATED，服务端记录
   `mfa_verified_at`，轮换为 FULL 令牌并作废旧受限令牌；每个受保护请求校验时间戳新鲜度
   （15 分钟），过期拒绝；敏感操作可要求 step-up 重新验证。
4. **越权 fail-closed + 审计**：`bypass_guard` 对伪造/过期令牌、未知资源、未完成 MFA、
   scope 不足、账户锁定等一律拒绝，所有允许/拒绝决策写审计日志。
5. **速率限制与锁定**：MFA 尝试有固定窗口限流，连续 5 次失败锁定账户 15 分钟；
   账号恢复（须证明身份）只解除锁定并回到半登录态，不会直接授予全认证。
6. **错误码映射**：内部错误经 `error_map` 转为对外安全消息与 HTTP 状态码，不泄漏内部细节。
7. **pairwise 测试矩阵**：`test_matrix` 贪心生成两两覆盖用例（含 client_flag 正反两面），
   并标注期望决策，证明客户端标志不影响授权结果。

## 测试

- `tests/test_mfa_state_machine.py`：15 个入口的契约测试。
- `tests/test_security_properties.py`：安全属性测试（标志伪造、受限令牌隔离、
  时间戳过期、step-up、限流锁定、账号恢复、审计留痕、pairwise 全覆盖）。

