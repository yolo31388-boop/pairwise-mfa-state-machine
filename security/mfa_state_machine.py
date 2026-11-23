"""MFA 服务端状态机 —— 安全参考实现。

修复要点（对应题目描述中的漏洞与修法）：

1. 认证状态只保存在服务端（SessionStore），客户端无法修改；客户端报上来的
   布尔标志（``session_flag``）不参与任何授权决策，仅用于展示和审计，
   因此「改响应跳过二次验证」不再可能。
2. 密码校验通过后只进入「半登录态」（HALF_AUTHENTICATED），发放受限令牌：
   短 TTL、scope 仅限 ``mfa:*`` 端点，不能访问任何受保护资源。
3. 二次因子校验成功后才升级为 FULLY_AUTHENTICATED，并在服务端记录验证
   时间戳；每个受保护请求都校验时间戳新鲜度，过期或敏感操作要求 step-up。
4. 越权访问一律 fail-closed 拒绝并写审计日志；MFA 尝试有速率限制，
   连续失败触发账户锁定；账号恢复后仍须重新走完整 MFA。
5. 内部错误码经 ``error_map`` 映射为对外安全消息，不泄漏内部实现细节。

所有入口函数都支持依赖注入（store / clock），默认使用模块级存储，
便于单元测试，也便于在真实框架中替换为 Redis / 数据库实现。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from enum import StrEnum
from typing import Any, Callable

# ---------------------------------------------------------------------------
# 常量与策略配置
# ---------------------------------------------------------------------------

RESTRICTED_TOKEN_TTL = 300      # 半登录态受限令牌：5 分钟
FULL_TOKEN_TTL = 3600           # 全认证令牌：1 小时
MAX_MFA_AGE = 900               # 二次验证时间戳有效期：15 分钟，过期需 step-up
MAX_MFA_ATTEMPTS = 5            # 连续 MFA 失败多少次后锁定
LOCKOUT_DURATION = 900          # 账户锁定时长：15 分钟
DEFAULT_RL_LIMIT = 10           # 默认速率限制：每窗口 10 次
DEFAULT_RL_WINDOW = 300         # 速率限制窗口：5 分钟

# 仅受限令牌（半登录态）允许访问的端点组：只能做 MFA 本身
MFA_ONLY_RESOURCES = frozenset(
    {"/mfa/challenge", "/mfa/verify", "/mfa/status"}
)

# 受保护资源 -> 访问所需的最小令牌 scope；未列出的资源一律拒绝（fail-closed）
ACCESS_POLICY: dict[str, "TokenScope"] = {
    "/mfa/challenge": None,  # 占位，下方统一填充
    "/mfa/verify": None,
    "/mfa/status": None,
    "/profile": None,
    "/orders": None,
    "/admin/users": None,
    "/admin/audit": None,
}


class MFAState(StrEnum):
    """服务端认证状态机的全部状态。"""

    ANONYMOUS = "anonymous"
    HALF_AUTHENTICATED = "half_authenticated"
    FULLY_AUTHENTICATED = "fully_authenticated"
    LOCKED = "locked"


class TokenScope(StrEnum):
    """令牌权限范围。"""

    NONE = "none"
    RESTRICTED = "restricted"   # 半登录态：仅 mfa:* 端点
    FULL = "full"               # MFA 通过后：全部受保护资源


for _r in MFA_ONLY_RESOURCES:
    ACCESS_POLICY[_r] = TokenScope.RESTRICTED
for _r in ("/profile", "/orders", "/admin/users", "/admin/audit"):
    ACCESS_POLICY[_r] = TokenScope.FULL


# ---------------------------------------------------------------------------
# 服务端存储（真实系统中应替换为 Redis / 数据库，客户端完全不可见）
# ---------------------------------------------------------------------------


class SessionStore:
    """服务端会话、令牌、限流、锁定、审计的统一存储。"""

    def __init__(self, key: bytes | None = None) -> None:
        # HMAC 签名密钥只存在于服务端
        self.key: bytes = key or secrets.token_bytes(32)
        self.sessions: dict[str, dict[str, Any]] = {}
        self.tokens: dict[str, dict[str, Any]] = {}
        self.rl_buckets: dict[str, dict[str, Any]] = {}
        self.lockouts: dict[Any, dict[str, Any]] = {}
        self.audit_log: list[dict[str, Any]] = []
        self.log_entries: list[dict[str, Any]] = []
        self.audit_seq = 0
        self.log_seq = 0

    def reset(self) -> None:
        self.__init__(self.key)


_DEFAULT_STORE = SessionStore()


def _now(clock: Callable[[], float] | float | None) -> float:
    """统一取时：clock 可以是可调用对象、显式 epoch 秒数，或 None（系统时钟）。"""
    if clock is None:
        return time.time()
    if callable(clock):
        return float(clock())
    return float(clock)


def _jsonable(value: Any) -> Any:
    """保证审计/日志内容可序列化，绝不因序列化失败而抛出。"""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def _encode(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _issue_token(
    store: SessionStore,
    session_id: str,
    scope: TokenScope,
    now: float,
    ttl: int,
) -> str:
    """签发 HMAC 签名令牌；令牌本体不存敏感状态，校验态只在服务端。"""
    payload = {
        "sid": session_id,
        "scope": str(scope),
        "iat": int(now),
        "exp": int(now + ttl),
    }
    token = hmac.new(store.key, _encode(payload), hashlib.sha256).hexdigest()
    store.tokens[token] = payload
    return token


def _inspect_token(
    store: SessionStore, token: Any, now: float
) -> tuple[dict[str, Any] | None, str | None]:
    """校验令牌签名与有效期，返回 (payload, 错误码)。"""
    if not isinstance(token, str) or token not in store.tokens:
        return None, "invalid_token"
    payload = store.tokens[token]
    expected = hmac.new(
        store.key, _encode(payload), hashlib.sha256
    ).hexdigest()
    # 常量时间比较，防时序侧信道
    if not hmac.compare_digest(expected, token):
        return None, "invalid_token"
    if now >= payload["exp"]:
        return None, "token_expired"
    return payload, None


def _decision(
    allowed: bool,
    reason: str,
    now: float,
    *,
    session_id: Any = None,
    state: MFAState | None = None,
    resource: Any = None,
    token_scope: TokenScope | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "allowed": allowed,
        "reason": reason,
        "at": now,
        "session_id": session_id,
        "state": str(state) if state is not None else None,
        "resource": resource,
        "token_scope": str(token_scope) if token_scope is not None else None,
    }
    if extra:
        result.update(extra)
    return result


# ---------------------------------------------------------------------------
# 1. 半登录态：密码正确但 MFA 未完成
# ---------------------------------------------------------------------------


def half_login(
    user_id: Any,
    password_ok: bool,
    store: SessionStore = _DEFAULT_STORE,
    clock: Callable[[], float] | float | None = None,
) -> dict[str, Any]:
    """密码校验通过后建立半登录会话，只发受限令牌。

    密码错误不建立任何会话，同样写审计。
    """
    now = _now(clock)
    if not password_ok:
        audit("login.password_failed", {"user_id": str(user_id)}, store, clock)
        return _decision(False, "invalid_credentials", now, state=MFAState.ANONYMOUS)

    session_id = secrets.token_hex(16)
    token = _issue_token(
        store, session_id, TokenScope.RESTRICTED, now, RESTRICTED_TOKEN_TTL
    )
    session = {
        "session_id": session_id,
        "user_id": user_id,
        "state": MFAState.HALF_AUTHENTICATED,
        "created_at": now,
        "mfa_verified_at": None,
        "token": token,
        "revoked": False,
        "step_up_required": False,
    }
    store.sessions[session_id] = session
    audit(
        "session.half_login",
        {"session_id": session_id, "user_id": str(user_id)},
        store,
        clock,
    )
    return _decision(
        True,
        "mfa_required",
        now,
        session_id=session_id,
        state=MFAState.HALF_AUTHENTICATED,
        token_scope=TokenScope.RESTRICTED,
        extra={
            "token": token,
            "token_expires_at": now + RESTRICTED_TOKEN_TTL,
            "mfa_required": True,
            "accessible_resources": sorted(MFA_ONLY_RESOURCES),
        },
    )


# ---------------------------------------------------------------------------
# 2. 受限令牌：只能访问 MFA 端点
# ---------------------------------------------------------------------------


def restricted_token(
    session_id: Any,
    resource: Any = None,
    store: SessionStore = _DEFAULT_STORE,
    clock: Callable[[], float] | float | None = None,
) -> dict[str, Any]:
    """评估受限令牌的能力范围：仅 mfa:* 端点，其余资源一律不可达。"""
    now = _now(clock)
    session = store.sessions.get(session_id)
    if session is None:
        return _decision(
            False, "session_not_found", now, session_id=session_id,
            state=MFAState.ANONYMOUS,
            extra={"accessible_resources": sorted(MFA_ONLY_RESOURCES)},
        )

    token = session.get("token")
    payload, err = _inspect_token(store, token, now)
    scope = TokenScope(payload["scope"]) if payload else TokenScope.NONE
    if resource is None:
        resource_allowed = None
    else:
        resource_allowed = (
            err is None
            and resource in MFA_ONLY_RESOURCES
            and scope in (TokenScope.RESTRICTED, TokenScope.FULL)
        )
    return _decision(
        err is None,
        err or "ok",
        now,
        session_id=session_id,
        state=session["state"],
        resource=resource,
        token_scope=scope,
        extra={
            "token": token,
            "token_valid": err is None,
            "expires_at": payload["exp"] if payload else None,
            "accessible_resources": sorted(MFA_ONLY_RESOURCES),
            "resource_allowed": resource_allowed,
        },
    )


# ---------------------------------------------------------------------------
# 3. 二次校验时间戳
# ---------------------------------------------------------------------------


def verify_timestamp(
    session_id: Any,
    max_age: float = MAX_MFA_AGE,
    store: SessionStore = _DEFAULT_STORE,
    clock: Callable[[], float] | float | None = None,
) -> dict[str, Any]:
    """校验服务端记录的 MFA 验证时间戳是否仍然新鲜。"""
    now = _now(clock)
    session = store.sessions.get(session_id)
    if session is None:
        return {
            "fresh": False,
            "allowed": False,
            "reason": "session_not_found",
            "session_id": session_id,
            "mfa_verified_at": None,
            "age": None,
            "max_age": max_age,
            "now": now,
        }
    verified_at = session.get("mfa_verified_at")
    if session["state"] != MFAState.FULLY_AUTHENTICATED or verified_at is None:
        return {
            "fresh": False,
            "allowed": False,
            "reason": "mfa_not_verified",
            "session_id": session_id,
            "mfa_verified_at": None,
            "age": None,
            "max_age": max_age,
            "now": now,
        }
    age = now - verified_at
    fresh = age <= max_age
    return {
        "fresh": fresh,
        "allowed": fresh,
        "reason": "ok" if fresh else "timestamp_expired",
        "session_id": session_id,
        "mfa_verified_at": verified_at,
        "age": age,
        "max_age": max_age,
        "now": now,
    }


# ---------------------------------------------------------------------------
# 4. 服务端权威状态
# ---------------------------------------------------------------------------


def server_state(
    session_id: Any,
    clock: Callable[[], float] | float | None = None,
    store: SessionStore = _DEFAULT_STORE,
) -> dict[str, Any]:
    """返回会话的服务端权威状态快照——客户端永远拿不到写权限。"""
    now = _now(clock)
    session = store.sessions.get(session_id)
    if session is None:
        return {
            "known": False,
            "authoritative": True,
            "session_id": session_id,
            "state": MFAState.ANONYMOUS,
            "user_id": None,
            "mfa_verified_at": None,
            "mfa_age": None,
            "step_up_required": False,
            "revoked": False,
            "lockout": None,
            "token_scope": TokenScope.NONE,
            "now": now,
        }
    verified_at = session.get("mfa_verified_at")
    lock = store.lockouts.get(session["user_id"])
    return {
        "known": True,
        "authoritative": True,
        "session_id": session_id,
        "state": session["state"],
        "user_id": session["user_id"],
        "created_at": session["created_at"],
        "mfa_verified_at": verified_at,
        "mfa_age": (now - verified_at) if verified_at is not None else None,
        "step_up_required": bool(session.get("step_up_required")),
        "revoked": bool(session.get("revoked")),
        "lockout": lock,
        "token_scope": (
            _inspect_token(store, session.get("token"), now)[0]
            and TokenScope(store.tokens[session["token"]]["scope"])
        ),
        "now": now,
    }


# ---------------------------------------------------------------------------
# 5. 审计日志
# ---------------------------------------------------------------------------


def audit(
    event: Any,
    result: Any = None,
    store: SessionStore = _DEFAULT_STORE,
    clock: Callable[[], float] | float | None = None,
) -> dict[str, Any]:
    """记录安全事件（登录、MFA 成败、越权、锁定、恢复等），返回审计条目。"""
    entry = {
        "id": store.audit_seq,
        "at": _now(clock),
        "event": str(event),
        "detail": _jsonable(result),
    }
    store.audit_seq += 1
    store.audit_log.append(entry)
    return entry


# ---------------------------------------------------------------------------
# 6. 越权防护（核心守卫）
# ---------------------------------------------------------------------------


def bypass_guard(
    token: Any,
    resource: Any = None,
    store: SessionStore = _DEFAULT_STORE,
    clock: Callable[[], float] | float | None = None,
) -> dict[str, Any]:
    """受保护资源的统一入口守卫，默认拒绝一切不满足条件的访问。"""
    now = _now(clock)

    # 1) 令牌必须真实、签名正确、未过期
    payload, err = _inspect_token(store, token, now)
    if err is not None:
        decision = _decision(False, err, now, resource=resource)
        audit("access.denied", decision, store, clock)
        return decision

    # 2) 会话必须存在且未吊销
    session = store.sessions.get(payload["sid"])
    if session is None:
        decision = _decision(False, "session_not_found", now, resource=resource)
        audit("access.denied", decision, store, clock)
        return decision
    if session.get("revoked"):
        decision = _decision(
            False, "session_revoked", now,
            session_id=session["session_id"], state=session["state"],
            resource=resource,
        )
        audit("access.denied", decision, store, clock)
        return decision

    # 3) 账户锁定检查（锁定到期自动解除）
    lock = store.lockouts.get(session["user_id"])
    if lock and lock.get("locked") and now < lock.get("until", 0):
        decision = _decision(
            False, "account_locked", now,
            session_id=session["session_id"], state=MFAState.LOCKED,
            resource=resource, token_scope=TokenScope(payload["scope"]),
            extra={"retry_after": max(0, int(lock["until"] - now))},
        )
        audit("access.denied", decision, store, clock)
        return decision
    if lock and lock.get("locked"):
        lock["locked"] = False

    scope = TokenScope(payload["scope"])

    # 4) 未知资源 fail-closed
    if resource not in ACCESS_POLICY:
        decision = _decision(
            False, "unknown_resource", now,
            session_id=session["session_id"], state=session["state"],
            resource=resource, token_scope=scope,
        )
        audit("access.denied", decision, store, clock)
        return decision

    required_scope = ACCESS_POLICY[resource]

    # 5) MFA 端点组：半登录态凭受限令牌即可访问，否则拒绝
    if required_scope == TokenScope.RESTRICTED:
        if scope not in (TokenScope.RESTRICTED, TokenScope.FULL):
            decision = _decision(
                False, "insufficient_scope", now,
                session_id=session["session_id"], state=session["state"],
                resource=resource, token_scope=scope,
            )
            audit("access.denied", decision, store, clock)
            return decision
        decision = _decision(
            True, "ok", now,
            session_id=session["session_id"], state=session["state"],
            resource=resource, token_scope=scope,
        )
        audit("access.allowed", decision, store, clock)
        return decision

    # 6) 受保护业务资源：必须完成 MFA
    if session["state"] != MFAState.FULLY_AUTHENTICATED:
        decision = _decision(
            False, "mfa_required", now,
            session_id=session["session_id"], state=session["state"],
            resource=resource, token_scope=scope,
        )
        audit("access.denied", decision, store, clock)
        return decision

    # 7) 敏感操作要求 step-up 重新验证
    if session.get("step_up_required"):
        decision = _decision(
            False, "step_up_required", now,
            session_id=session["session_id"], state=session["state"],
            resource=resource, token_scope=scope,
        )
        audit("access.denied", decision, store, clock)
        return decision

    # 8) 二次验证时间戳必须新鲜
    ts = verify_timestamp(session["session_id"], MAX_MFA_AGE, store=store, clock=clock)
    if not ts["allowed"]:
        decision = _decision(
            False, ts["reason"], now,
            session_id=session["session_id"], state=session["state"],
            resource=resource, token_scope=scope,
            extra={"mfa_age": ts["age"]},
        )
        audit("access.denied", decision, store, clock)
        return decision

    # 9) 全认证资源要求 FULL scope
    if scope != TokenScope.FULL:
        decision = _decision(
            False, "insufficient_scope", now,
            session_id=session["session_id"], state=session["state"],
            resource=resource, token_scope=scope,
        )
        audit("access.denied", decision, store, clock)
        return decision

    decision = _decision(
        True, "ok", now,
        session_id=session["session_id"], state=session["state"],
        resource=resource, token_scope=scope,
    )
    audit("access.allowed", decision, store, clock)
    return decision


# ---------------------------------------------------------------------------
# 7. 会话布尔标志：只读取服务端状态，客户端声称值被忽略
# ---------------------------------------------------------------------------


def session_flag(
    session_id: Any,
    client_claimed: Any = None,
    store: SessionStore = _DEFAULT_STORE,
) -> dict[str, Any]:
    """返回 MFA 是否通过的权威布尔值；客户端声称的标志永远被忽略。"""
    session = store.sessions.get(session_id)
    claimed = bool(client_claimed)
    if session is None:
        return {
            "session_id": session_id,
            "authoritative": True,
            "trusted": False,
            "mfa_passed": False,
            "state": MFAState.ANONYMOUS,
            "client_claimed": claimed,
            "client_claimed_ignored": True,
            "reason": "session_not_found",
        }
    mfa_passed = session["state"] == MFAState.FULLY_AUTHENTICATED
    return {
        "session_id": session_id,
        "authoritative": True,
        "trusted": mfa_passed,
        "mfa_passed": mfa_passed,
        "state": session["state"],
        "client_claimed": claimed,
        # 无论客户端声称 True 还是 False，决策都以服务端状态为准
        "client_claimed_ignored": True,
        "reason": "ok",
    }


# ---------------------------------------------------------------------------
# 8. Step-up 重新认证
# ---------------------------------------------------------------------------


def step_up(
    session_id: Any,
    required: bool = True,
    store: SessionStore = _DEFAULT_STORE,
    clock: Callable[[], float] | float | None = None,
) -> dict[str, Any]:
    """标记/解除会话的 step-up 要求；标记后敏感资源访问将被拒绝直至重新验证。"""
    now = _now(clock)
    session = store.sessions.get(session_id)
    if session is None:
        return _decision(
            False, "session_not_found", now,
            session_id=session_id, state=MFAState.ANONYMOUS,
            extra={"step_up_required": bool(required)},
        )
    session["step_up_required"] = bool(required)
    audit(
        "step_up." + ("required" if required else "cleared"),
        {"session_id": session_id},
        store,
        clock,
    )
    return _decision(
        True, "ok", now,
        session_id=session_id, state=session["state"],
        extra={"step_up_required": bool(required)},
    )


# ---------------------------------------------------------------------------
# 9. 输入校验（MFA 验证码）
# ---------------------------------------------------------------------------

_CODE_PATTERN = re.compile(r"^\d{6}$")


def validation(code: Any, expected: Any) -> dict[str, Any]:
    """校验 6 位数字 MFA 验证码，使用常量时间比较防时序攻击。"""
    if code is None or expected is None:
        return {"valid": False, "reason": "missing_input"}
    code_s = str(code).strip()
    expected_s = str(expected).strip()
    if not _CODE_PATTERN.fullmatch(code_s):
        return {"valid": False, "reason": "bad_code_format"}
    if not _CODE_PATTERN.fullmatch(expected_s):
        return {"valid": False, "reason": "bad_expected_format"}
    valid = hmac.compare_digest(code_s, expected_s)
    return {"valid": valid, "reason": "ok" if valid else "code_mismatch"}


# ---------------------------------------------------------------------------
# 10. 错误码映射：内部错误 -> 对外安全消息
# ---------------------------------------------------------------------------

_INTERNAL_ERROR_MAP: dict[str, tuple[str, int]] = {
    "invalid_credentials": ("用户名或密码错误", 401),
    "mfa_required": ("二次验证未完成，请先完成 MFA", 401),
    "mfa_not_verified": ("二次验证未完成，请先完成 MFA", 401),
    "invalid_token": ("认证令牌无效", 401),
    "token_expired": ("认证令牌已过期，请重新登录", 401),
    "timestamp_expired": ("二次验证已过期，请重新验证", 401),
    "session_not_found": ("会话不存在或已失效，请重新登录", 401),
    "session_revoked": ("会话已被吊销，请重新登录", 401),
    "step_up_required": ("该操作需要重新进行身份验证", 401),
    "insufficient_scope": ("无权访问该资源", 403),
    "account_locked": ("账户已临时锁定，请稍后再试或通过账号恢复流程解锁", 423),
    "rate_limited": ("操作过于频繁，请稍后再试", 429),
    "unknown_resource": ("资源不存在", 404),
    "bad_code_format": ("验证码格式错误，应为 6 位数字", 400),
    "code_mismatch": ("验证码错误", 401),
    "recovery_rejected": ("账号恢复凭证无效", 403),
}


def error_map(code: Any, detail: Any = None) -> dict[str, Any]:
    """把内部错误码映射为可对外暴露的安全消息与 HTTP 状态码。

    ``detail`` 中的内部细节只会被吞掉（不回传客户端），避免信息泄漏。
    """
    key = str(code)
    message, http_status = _INTERNAL_ERROR_MAP.get(key, ("请求被安全策略拒绝", 403))
    return {
        "code": key,
        "message": message,
        "http_status": http_status,
        "safe_for_client": True,
        "internal_detail_exposed": False,
    }


# ---------------------------------------------------------------------------
# 11. 速率限制
# ---------------------------------------------------------------------------


def rate_limit(
    key: Any,
    limit: int = DEFAULT_RL_LIMIT,
    window: int = DEFAULT_RL_WINDOW,
    store: SessionStore = _DEFAULT_STORE,
    clock: Callable[[], float] | float | None = None,
) -> dict[str, Any]:
    """固定窗口速率限制，超限拒绝并审计。"""
    now = _now(clock)
    try:
        limit = int(limit)
        window = int(window)
    except (TypeError, ValueError):
        limit, window = DEFAULT_RL_LIMIT, DEFAULT_RL_WINDOW
    if limit < 1:
        limit = 1
    if window < 1:
        window = DEFAULT_RL_WINDOW

    bucket = store.rl_buckets.get(str(key))
    if bucket is None or now >= bucket["reset_at"]:
        bucket = {"count": 0, "reset_at": now + window, "limit": limit, "window": window}
        store.rl_buckets[str(key)] = bucket
    bucket["count"] += 1
    allowed = bucket["count"] <= limit
    result = {
        "key": str(key),
        "allowed": allowed,
        "attempts": bucket["count"],
        "limit": limit,
        "remaining": max(0, limit - bucket["count"]),
        "reset_at": bucket["reset_at"],
        "retry_after": max(0, int(bucket["reset_at"] - now)),
    }
    if not allowed:
        audit("rate_limit.exceeded", {"key": str(key), "attempts": bucket["count"]}, store, clock)
    return result


# ---------------------------------------------------------------------------
# 12. 账户锁定
# ---------------------------------------------------------------------------


def _register_mfa_failure(
    user_id: Any, store: SessionStore, now: float
) -> dict[str, Any]:
    """登记一次 MFA 失败，达到阈值即锁定。"""
    rec = store.lockouts.setdefault(
        user_id,
        {"failures": 0, "locked": False, "until": 0.0, "last_failure_at": None},
    )
    rec["failures"] += 1
    rec["last_failure_at"] = now
    if rec["failures"] >= MAX_MFA_ATTEMPTS and not rec["locked"]:
        rec["locked"] = True
        rec["until"] = now + LOCKOUT_DURATION
        audit(
            "account.locked",
            {"user_id": str(user_id), "until": rec["until"], "failures": rec["failures"]},
            store,
            now,
        )
    return rec


def lockout(
    user_id: Any,
    reset: bool = False,
    store: SessionStore = _DEFAULT_STORE,
    clock: Callable[[], float] | float | None = None,
) -> dict[str, Any]:
    """查询锁定状态；``reset=True`` 为管理员/恢复流程显式解锁（带审计）。"""
    now = _now(clock)
    rec = store.lockouts.get(user_id)
    if reset:
        rec = store.lockouts.setdefault(
            user_id,
            {"failures": 0, "locked": False, "until": 0.0, "last_failure_at": None},
        )
        rec["failures"] = 0
        rec["locked"] = False
        rec["until"] = 0.0
        audit("lockout.reset", {"user_id": str(user_id)}, store, clock)
    if rec is None:
        return {
            "user_id": user_id,
            "locked": False,
            "failures": 0,
            "remaining_attempts": MAX_MFA_ATTEMPTS,
            "until": None,
            "retry_after": 0,
        }
    locked = bool(rec["locked"]) and now < rec["until"]
    if rec["locked"] and not locked:
        rec["locked"] = False  # 锁定到期自动解除
    return {
        "user_id": user_id,
        "locked": locked,
        "failures": rec["failures"],
        "remaining_attempts": max(0, MAX_MFA_ATTEMPTS - rec["failures"]),
        "until": rec["until"] if locked else None,
        "retry_after": max(0, int(rec["until"] - now)) if locked else 0,
    }


# ---------------------------------------------------------------------------
# 13. 账号恢复：证明身份后解锁，但绝不直接给全认证
# ---------------------------------------------------------------------------


def recovery(
    user_id: Any,
    proof_ok: bool,
    store: SessionStore = _DEFAULT_STORE,
    clock: Callable[[], float] | float | None = None,
) -> dict[str, Any]:
    """账号恢复：凭证有效则解除锁定并建立半登录会话，仍须重新完成 MFA。"""
    now = _now(clock)
    if not proof_ok:
        audit("recovery.rejected", {"user_id": str(user_id)}, store, clock)
        return _decision(
            False, "recovery_rejected", now,
            state=MFAState.ANONYMOUS,
            extra={"user_id": user_id},
        )
    rec = store.lockouts.get(user_id)
    if rec is not None:
        rec["failures"] = 0
        rec["locked"] = False
        rec["until"] = 0.0
    audit("recovery.succeeded", {"user_id": str(user_id)}, store, clock)
    # 恢复不等于认证：重新走「密码 + MFA」，这里只给半登录态
    result = half_login(user_id, True, store=store, clock=clock)
    result["reason"] = "recovery_ok_mfa_required"
    result["recovery"] = True
    return result


# ---------------------------------------------------------------------------
# 14. 结构化安全日志
# ---------------------------------------------------------------------------


def logging(
    event: Any,
    result: Any = None,
    store: SessionStore = _DEFAULT_STORE,
    clock: Callable[[], float] | float | None = None,
    level: str = "info",
) -> dict[str, Any]:
    """输出结构化日志条目（与审计流分开存储），任何输入都不会抛异常。"""
    entry = {
        "id": store.log_seq,
        "at": _now(clock),
        "level": str(level),
        "event": str(event),
        "detail": _jsonable(result),
    }
    store.log_seq += 1
    store.log_entries.append(entry)
    return entry


# ---------------------------------------------------------------------------
# 15. Pairwise 组合测试矩阵
# ---------------------------------------------------------------------------

DEFAULT_TEST_DIMENSIONS: dict[str, list[str]] = {
    "session_state": [
        MFAState.ANONYMOUS,
        MFAState.HALF_AUTHENTICATED,
        MFAState.FULLY_AUTHENTICATED,
        MFAState.LOCKED,
    ],
    "token_scope": [TokenScope.NONE, TokenScope.RESTRICTED, TokenScope.FULL],
    "token_age": ["fresh", "expired"],
    "resource_group": ["mfa", "profile", "admin"],
    "client_flag": [False, True],
}


def _pairwise_cases(dims: dict[str, list[Any]]) -> list[dict[str, Any]]:
    """贪心构造 pairwise（两两覆盖）用例集，保证每个维度值对至少出现一次。"""
    names = list(dims)
    domains = [list(dims[name]) for name in names]

    universe: set[tuple[int, int, Any, Any]] = set()
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            for a in domains[i]:
                for b in domains[j]:
                    universe.add((i, j, a, b))

    remaining = set(universe)
    rows: list[tuple[Any, ...]] = []
    while remaining:
        best_row: tuple[Any, ...] | None = None
        best_score = -1
        # 以每个未覆盖对为种子构造候选行，选覆盖新增对最多的
        for i, j, a, b in list(remaining):
            row: list[Any] = [None] * len(names)
            row[i], row[j] = a, b
            for k in range(len(names)):
                if row[k] is not None:
                    continue
                best_val, best_cov = domains[k][0], -1
                for val in domains[k]:
                    row[k] = val
                    cov = sum(
                        1
                        for x, y, va, vb in remaining
                        if row[x] is not None
                        and row[y] is not None
                        and row[x] == va
                        and row[y] == vb
                    )
                    if cov > best_cov:
                        best_cov, best_val = cov, val
                row[k] = best_val
            candidate = tuple(row)
            score = sum(
                1
                for x, y, va, vb in remaining
                if candidate[x] == va and candidate[y] == vb
            )
            if score > best_score:
                best_score, best_row = score, candidate
        assert best_row is not None
        rows.append(best_row)
        remaining = {
            pair
            for pair in remaining
            if not (best_row[pair[0]] == pair[2] and best_row[pair[1]] == pair[3])
        }

    return [dict(zip(names, row)) for row in rows]


def _expected_decision(case: dict[str, Any]) -> str:
    """根据状态机策略推导单条 pairwise 用例的期望决策（client_flag 不参与）。"""
    if case["session_state"] == MFAState.LOCKED:
        return "deny:account_locked"
    if case["token_age"] == "expired":
        return "deny:token_expired"
    if case["token_scope"] == TokenScope.NONE:
        return "deny:invalid_token"
    if case["resource_group"] == "mfa":
        if case["session_state"] == MFAState.ANONYMOUS:
            return "deny:mfa_required"
        if case["token_scope"] in (TokenScope.RESTRICTED, TokenScope.FULL):
            return "allow"
        return "deny:insufficient_scope"
    # profile / admin 等受保护资源
    if case["session_state"] != MFAState.FULLY_AUTHENTICATED:
        return "deny:mfa_required"
    if case["token_scope"] != TokenScope.FULL:
        return "deny:insufficient_scope"
    return "allow"


def test_matrix(
    dims: dict[str, list[Any]] | None = None,
    store: Any = None,
) -> dict[str, Any]:
    """生成 pairwise 组合测试矩阵，并标注每条用例的期望授权决策。

    矩阵中刻意同时包含 client_flag=True/False 的用例：期望决策完全相同，
    用以证明客户端布尔标志无法影响服务端授权。
    """
    if not isinstance(dims, dict) or not dims:
        dims = DEFAULT_TEST_DIMENSIONS
    # 只保留非空、可迭代的维度
    safe_dims = {
        str(name): list(values)
        for name, values in dims.items()
        if isinstance(values, (list, tuple, set, frozenset)) and len(values) > 0
    }
    if not safe_dims:
        safe_dims = DEFAULT_TEST_DIMENSIONS

    pair_count = 0
    domain_lens = [len(v) for v in safe_dims.values()]
    for i in range(len(domain_lens)):
        for j in range(i + 1, len(domain_lens)):
            pair_count += domain_lens[i] * domain_lens[j]

    cases = _pairwise_cases(safe_dims)
    for case in cases:
        case["expected_decision"] = _expected_decision(case)

    return {
        "dimensions": {name: [str(v) for v in values] for name, values in safe_dims.items()},
        "pairwise_cases": [{k: (str(v) if k != "client_flag" else v) for k, v in case.items()} for case in cases],
        "case_count": len(cases),
        "pair_count": pair_count,
        "covered_pairs": pair_count,
        "all_pairs_covered": True,
        "client_flag_influences_decision": False,
    }


# ---------------------------------------------------------------------------
# 二次因子校验主流程（供 half_login -> FULLY_AUTHENTICATED 的状态迁移使用）
# ---------------------------------------------------------------------------


def complete_mfa(
    session_id: Any,
    code: Any,
    expected_code: Any,
    store: SessionStore = _DEFAULT_STORE,
    clock: Callable[[], float] | float | None = None,
) -> dict[str, Any]:
    """校验二次因子：成功则升级全认证、盖服务端时间戳并轮换为 FULL 令牌。

    失败计入速率限制与账户锁定。任何情况下客户端都无法自行推动状态迁移。
    """
    now = _now(clock)
    session = store.sessions.get(session_id)
    if session is None:
        return _decision(
            False, "session_not_found", now,
            session_id=session_id, state=MFAState.ANONYMOUS,
        )
    if session.get("revoked"):
        return _decision(
            False, "session_revoked", now,
            session_id=session_id, state=session["state"],
        )

    # 先过速率限制（粗节流阀，阈值高于锁定阈值，保证锁定先生效），再查锁定
    rl = rate_limit(
        f"mfa:{session_id}", DEFAULT_RL_LIMIT, DEFAULT_RL_WINDOW,
        store=store, clock=clock,
    )
    if not rl["allowed"]:
        decision = _decision(
            False, "rate_limited", now,
            session_id=session_id, state=session["state"],
            extra={"retry_after": rl["retry_after"]},
        )
        audit("mfa.denied", decision, store, clock)
        return decision

    lock = lockout(session["user_id"], store=store, clock=clock)
    if lock["locked"]:
        decision = _decision(
            False, "account_locked", now,
            session_id=session_id, state=MFAState.LOCKED,
            extra={"retry_after": lock["retry_after"]},
        )
        audit("mfa.denied", decision, store, clock)
        return decision

    verdict = validation(code, expected_code)
    if not verdict["valid"]:
        rec = _register_mfa_failure(session["user_id"], store, now)
        audit(
            "mfa.failed",
            {
                "session_id": session_id,
                "user_id": str(session["user_id"]),
                "reason": verdict["reason"],
                "failures": rec["failures"],
            },
            store,
            clock,
        )
        return _decision(
            False, verdict["reason"], now,
            session_id=session_id, state=session["state"],
            extra={"remaining_attempts": max(0, MAX_MFA_ATTEMPTS - rec["failures"])},
        )

    # 成功：状态迁移 + 服务端时间戳 + 令牌轮换（旧受限令牌作废）
    old_token = session.get("token")
    if old_token is not None:
        store.tokens.pop(old_token, None)
    token = _issue_token(
        store, session_id, TokenScope.FULL, now, FULL_TOKEN_TTL
    )
    session["state"] = MFAState.FULLY_AUTHENTICATED
    session["mfa_verified_at"] = now
    session["step_up_required"] = False
    session["token"] = token

    rec = store.lockouts.get(session["user_id"])
    if rec is not None:
        rec["failures"] = 0
        rec["locked"] = False
        rec["until"] = 0.0

    audit(
        "mfa.succeeded",
        {"session_id": session_id, "user_id": str(session["user_id"]), "at": now},
        store,
        clock,
    )
    return _decision(
        True, "ok", now,
        session_id=session_id, state=MFAState.FULLY_AUTHENTICATED,
        token_scope=TokenScope.FULL,
        extra={
            "token": token,
            "token_expires_at": now + FULL_TOKEN_TTL,
            "mfa_verified_at": now,
        },
    )
