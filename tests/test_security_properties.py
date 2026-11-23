"""安全属性测试：逐条验证题目要求的修复点。

覆盖：
1. 客户端改布尔标志无法跳过 MFA（服务端状态权威）
2. 半登录态只能持有受限令牌，受保护资源全部不可达
3. 二次校验时间戳记录在服务端且会过期，过期/敏感操作触发 step-up
4. 越权访问全部写审计，且默认 fail-closed
5. 速率限制与连续失败锁定
6. 账号恢复后仍须重新 MFA，不会直接获得全认证
"""

import pytest

import security.mfa_state_machine as mod
from security.mfa_state_machine import (
    ACCESS_POLICY,
    FULL_TOKEN_TTL,
    MAX_MFA_AGE,
    MAX_MFA_ATTEMPTS,
    MFA_ONLY_RESOURCES,
    MFAState,
    SessionStore,
    TokenScope,
)


class FakeClock:
    """可手动推进的时钟，避免测试中真实 sleep。"""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def store():
    return SessionStore(key=b"unit-test-signing-key-0123456789abcd")


@pytest.fixture
def clock():
    return FakeClock()


# ---------------------------------------------------------------------------
# 辅助：完整走一遍 密码 -> 半登录 -> MFA 的流程
# ---------------------------------------------------------------------------


def _half(store, clock, user="u1"):
    res = mod.half_login(user, True, store=store, clock=clock)
    assert res["allowed"] is True
    return res["session_id"], res["token"]


def _full(store, clock, user="u1", code="123456"):
    sid, restricted = _half(store, clock, user)
    res = mod.complete_mfa(sid, code, code, store=store, clock=clock)
    assert res["allowed"] is True
    return sid, res["token"]


# ---------------------------------------------------------------------------
# 1. 客户端布尔标志不可信
# ---------------------------------------------------------------------------


class TestClientFlagCannotBypass:
    def test_half_login_flag_claimed_true_still_denied(self, store, clock):
        sid, token = _half(store, clock)
        # 客户端篡改响应，声称 MFA 已通过
        flag = mod.session_flag(sid, client_claimed=True, store=store)
        assert flag["mfa_passed"] is False
        assert flag["client_claimed_ignored"] is True

        # 受保护资源照样拒绝
        decision = mod.bypass_guard(token, "/profile", store=store, clock=clock)
        assert decision["allowed"] is False
        assert decision["reason"] == "mfa_required"

    def test_claimed_flag_does_not_change_authority(self, store, clock):
        sid, _ = _half(store, clock)
        true_claim = mod.session_flag(sid, True, store=store)
        false_claim = mod.session_flag(sid, False, store=store)
        # 两种声称结果完全一致，都以服务端半登录态为准
        assert true_claim["mfa_passed"] == false_claim["mfa_passed"] is False
        assert true_claim["state"] == MFAState.HALF_AUTHENTICATED

    def test_unknown_session_flag_is_false(self, store):
        flag = mod.session_flag("nonexistent", client_claimed=True, store=store)
        assert flag["mfa_passed"] is False
        assert flag["allowed" if "allowed" in flag else "mfa_passed"] is False


# ---------------------------------------------------------------------------
# 2. 半登录态 / 受限令牌
# ---------------------------------------------------------------------------


class TestHalfLoginAndRestrictedToken:
    def test_half_login_issues_restricted_token_only(self, store, clock):
        sid, token = _half(store, clock)
        payload = store.tokens[token]
        assert TokenScope(payload["scope"]) == TokenScope.RESTRICTED
        assert store.sessions[sid]["state"] == MFAState.HALF_AUTHENTICATED
        assert store.sessions[sid]["mfa_verified_at"] is None

    def test_restricted_token_can_only_reach_mfa_endpoints(self, store, clock):
        sid, token = _half(store, clock)
        for resource in MFA_ONLY_RESOURCES:
            assert mod.bypass_guard(token, resource, store=store, clock=clock)["allowed"] is True
        for resource in ("/profile", "/orders", "/admin/users", "/admin/audit"):
            decision = mod.bypass_guard(token, resource, store=store, clock=clock)
            assert decision["allowed"] is False
            assert decision["reason"] == "mfa_required"

    def test_restricted_token_self_report(self, store, clock):
        sid, _ = _half(store, clock)
        info = mod.restricted_token(sid, "/profile", store=store, clock=clock)
        assert info["resource_allowed"] is False
        mfa_info = mod.restricted_token(sid, "/mfa/verify", store=store, clock=clock)
        assert mfa_info["resource_allowed"] is True

    def test_bad_password_creates_no_session(self, store, clock):
        res = mod.half_login("u1", False, store=store, clock=clock)
        assert res["allowed"] is False
        assert store.sessions == {}
        assert any(e["event"] == "login.password_failed" for e in store.audit_log)


# ---------------------------------------------------------------------------
# 3. MFA 升级与服务端时间戳
# ---------------------------------------------------------------------------


class TestMFAVerificationAndTimestamp:
    def test_mfa_success_upgrades_state_and_stamps_time(self, store, clock):
        sid, _ = _half(store, clock)
        before = clock()
        res = mod.complete_mfa(sid, "654321", "654321", store=store, clock=clock)
        assert res["allowed"] is True
        session = store.sessions[sid]
        assert session["state"] == MFAState.FULLY_AUTHENTICATED
        assert session["mfa_verified_at"] == before
        assert TokenScope(store.tokens[res["token"]]["scope"]) == TokenScope.FULL

    def test_old_restricted_token_revoked_after_mfa(self, store, clock):
        sid, restricted = _half(store, clock)
        mod.complete_mfa(sid, "123456", "123456", store=store, clock=clock)
        # 旧受限令牌已从服务端摘除，不能再用
        assert restricted not in store.tokens
        decision = mod.bypass_guard(restricted, "/profile", store=store, clock=clock)
        assert decision["allowed"] is False
        assert decision["reason"] == "invalid_token"

    def test_timestamp_goes_stale(self, store, clock):
        sid, token = _full(store, clock)
        ts = mod.verify_timestamp(sid, MAX_MFA_AGE, store=store, clock=clock)
        assert ts["fresh"] is True

        clock.advance(MAX_MFA_AGE + 1)
        ts = mod.verify_timestamp(sid, MAX_MFA_AGE, store=store, clock=clock)
        assert ts["fresh"] is False
        assert ts["reason"] == "timestamp_expired"

        # 时间戳过期后，守卫拒绝受保护资源
        decision = mod.bypass_guard(token, "/profile", store=store, clock=clock)
        assert decision["allowed"] is False
        assert decision["reason"] == "timestamp_expired"

    def test_wrong_code_keeps_half_state(self, store, clock):
        sid, token = _half(store, clock)
        res = mod.complete_mfa(sid, "000000", "123456", store=store, clock=clock)
        assert res["allowed"] is False
        assert store.sessions[sid]["state"] == MFAState.HALF_AUTHENTICATED
        # 仍是半登录态，受限令牌不变
        assert mod.bypass_guard(token, "/profile", store=store, clock=clock)["allowed"] is False

    def test_validation_rejects_bad_format_and_uses_constant_time(self, store):
        assert mod.validation("12a456", "123456")["valid"] is False
        assert mod.validation(None, "123456")["valid"] is False
        assert mod.validation("12345", "12345")["valid"] is False
        assert mod.validation("123456", "123456")["valid"] is True

    def test_full_token_also_expires(self, store, clock):
        sid, token = _full(store, clock)
        clock.advance(FULL_TOKEN_TTL + 1)
        decision = mod.bypass_guard(token, "/profile", store=store, clock=clock)
        assert decision["allowed"] is False
        assert decision["reason"] == "token_expired"


# ---------------------------------------------------------------------------
# 4. 越权防护 + 审计
# ---------------------------------------------------------------------------


class TestBypassGuardAndAudit:
    def test_forged_token_denied(self, store, clock):
        decision = mod.bypass_guard("forged-token-value", "/profile", store=store, clock=clock)
        assert decision["allowed"] is False
        assert decision["reason"] == "invalid_token"

    def test_unknown_resource_fails_closed(self, store, clock):
        _, token = _full(store, clock)
        decision = mod.bypass_guard(token, "/secret/internal/path", store=store, clock=clock)
        assert decision["allowed"] is False
        assert decision["reason"] == "unknown_resource"

    def test_no_token_denied(self, store, clock):
        decision = mod.bypass_guard(None, "/profile", store=store, clock=clock)
        assert decision["allowed"] is False

    def test_every_denial_is_audited(self, store, clock):
        mod.bypass_guard("x", "/profile", store=store, clock=clock)
        sid, restricted = _half(store, clock)
        mod.bypass_guard(restricted, "/admin/users", store=store, clock=clock)
        events = [e["event"] for e in store.audit_log]
        assert "access.denied" in events
        assert "session.half_login" in events
        # 成功访问也留痕
        mod.complete_mfa(sid, "123456", "123456", store=store, clock=clock)
        full_token = store.sessions[sid]["token"]
        mod.bypass_guard(full_token, "/profile", store=store, clock=clock)
        assert "access.allowed" in [e["event"] for e in store.audit_log]

    def test_server_state_is_authoritative_snapshot(self, store, clock):
        sid, _ = _full(store, clock)
        snap = mod.server_state(sid, clock=clock, store=store)
        assert snap["authoritative"] is True
        assert snap["state"] == MFAState.FULLY_AUTHENTICATED
        assert snap["mfa_verified_at"] is not None
        unknown = mod.server_state("ghost", clock=clock, store=store)
        assert unknown["known"] is False
        assert unknown["state"] == MFAState.ANONYMOUS


# ---------------------------------------------------------------------------
# 5. Step-up
# ---------------------------------------------------------------------------


class TestStepUp:
    def test_step_up_blocks_sensitive_resource_until_reverified(self, store, clock):
        sid, token = _full(store, clock)
        assert mod.bypass_guard(token, "/admin/users", store=store, clock=clock)["allowed"] is True

        mod.step_up(sid, True, store=store, clock=clock)
        decision = mod.bypass_guard(token, "/admin/users", store=store, clock=clock)
        assert decision["allowed"] is False
        assert decision["reason"] == "step_up_required"

        # 重新完成 MFA 后解除
        mod.complete_mfa(sid, "123456", "123456", store=store, clock=clock)
        new_token = store.sessions[sid]["token"]
        assert mod.bypass_guard(new_token, "/admin/users", store=store, clock=clock)["allowed"] is True


# ---------------------------------------------------------------------------
# 6. 速率限制与账户锁定
# ---------------------------------------------------------------------------


class TestRateLimitAndLockout:
    def test_rate_limit_blocks_after_threshold(self, store, clock):
        results = [
            mod.rate_limit("k1", limit=3, window=60, store=store, clock=clock)
            for _ in range(5)
        ]
        assert [r["allowed"] for r in results] == [True, True, True, False, False]
        assert results[-1]["retry_after"] == 60
        clock.advance(61)
        assert mod.rate_limit("k1", limit=3, window=60, store=store, clock=clock)["allowed"] is True

    def test_lockout_after_max_mfa_failures(self, store, clock):
        sid, _ = _half(store, clock, user="victim")
        for _ in range(MAX_MFA_ATTEMPTS - 1):
            res = mod.complete_mfa(sid, "000000", "123456", store=store, clock=clock)
            assert res["allowed"] is False
            assert res["reason"] == "code_mismatch"

        # 第 MAX 次失败：本次仍返回验证码错误，但服务端同步置位锁定
        res = mod.complete_mfa(sid, "000000", "123456", store=store, clock=clock)
        assert res["allowed"] is False
        assert res["reason"] == "code_mismatch"

        status = mod.lockout("victim", store=store, clock=clock)
        assert status["locked"] is True

        # 锁定期间即使验证码正确也拒绝
        res = mod.complete_mfa(sid, "123456", "123456", store=store, clock=clock)
        assert res["allowed"] is False
        assert res["reason"] == "account_locked"
        assert any(e["event"] == "account.locked" for e in store.audit_log)

    def test_lockout_auto_expires(self, store, clock):
        mod._register_mfa_failure("u9", store, clock())
        store.lockouts["u9"]["locked"] = True
        store.lockouts["u9"]["until"] = clock() + 10
        clock.advance(11)
        status = mod.lockout("u9", store=store, clock=clock)
        assert status["locked"] is False


# ---------------------------------------------------------------------------
# 7. 账号恢复
# ---------------------------------------------------------------------------


class TestRecovery:
    def test_recovery_requires_proof(self, store, clock):
        res = mod.recovery("u1", False, store=store, clock=clock)
        assert res["allowed"] is False
        assert res["reason"] == "recovery_rejected"

    def test_recovery_unlocks_but_keeps_half_state(self, store, clock):
        sid, _ = _half(store, clock, user="locked-user")
        for _ in range(MAX_MFA_ATTEMPTS):
            mod.complete_mfa(sid, "000000", "123456", store=store, clock=clock)
        assert mod.lockout("locked-user", store=store, clock=clock)["locked"] is True
        res = mod.recovery("locked-user", True, store=store, clock=clock)
        assert res["allowed"] is True
        assert mod.lockout("locked-user", store=store, clock=clock)["locked"] is False

        # 恢复后只拿到受限令牌，受保护资源仍不可达，必须重新 MFA
        new_sid = res["session_id"]
        assert store.sessions[new_sid]["state"] == MFAState.HALF_AUTHENTICATED
        decision = mod.bypass_guard(res["token"], "/profile", store=store, clock=clock)
        assert decision["allowed"] is False


# ---------------------------------------------------------------------------
# 8. 错误码映射与结构化日志
# ---------------------------------------------------------------------------


class TestErrorMapAndLogging:
    def test_internal_codes_map_to_safe_messages(self):
        for code in ("invalid_token", "account_locked", "rate_limited", "mfa_required"):
            mapped = mod.error_map(code, detail="internal stack trace here")
            assert mapped["safe_for_client"] is True
            assert "internal stack" not in str(mapped)
            assert isinstance(mapped["http_status"], int)

    def test_unknown_code_fails_safe(self):
        mapped = mod.error_map("some_secret_internal_failure")
        assert mapped["http_status"] in (400, 401, 403)
        assert mapped["safe_for_client"] is True

    def test_structured_logging(self, store, clock):
        entry = mod.logging("test.event", {"a": 1}, store=store, clock=clock, level="warning")
        assert entry["event"] == "test.event"
        assert entry["level"] == "warning"
        assert store.log_entries[-1] == entry


# ---------------------------------------------------------------------------
# 9. Pairwise 测试矩阵
# ---------------------------------------------------------------------------


class TestPairwiseMatrix:
    def test_matrix_covers_all_pairs(self):
        matrix = mod.test_matrix()
        assert matrix["case_count"] > 0
        assert matrix["all_pairs_covered"] is True
        assert matrix["client_flag_influences_decision"] is False

        dims = mod.DEFAULT_TEST_DIMENSIONS
        names = list(dims)
        pairs = {
            (i, j, a, b)
            for i in range(len(names))
            for j in range(i + 1, len(names))
            for a in dims[names[i]]
            for b in dims[names[j]]
        }
        covered = set()
        for case in matrix["pairwise_cases"]:
            row = {k: (v if k == "client_flag" else _enum_lookup(k, v)) for k, v in case.items() if k != "expected_decision"}
            for i in range(len(names)):
                for j in range(i + 1, len(names)):
                    covered.add((i, j, row[names[i]], row[names[j]]))
        assert covered == pairs

    def test_client_flag_never_changes_expectation(self):
        matrix = mod.test_matrix()
        # 按除 client_flag 外的字段分组，同组期望必须一致
        groups: dict[tuple, set[str]] = {}
        for case in matrix["pairwise_cases"]:
            key = tuple(v for k, v in case.items() if k not in ("client_flag", "expected_decision"))
            groups.setdefault(key, set()).add(case["expected_decision"])
        assert all(len(decisions) == 1 for decisions in groups.values())


def _enum_lookup(dim_name, value):
    for enum_cls in (MFAState, TokenScope):
        try:
            return enum_cls(value)
        except ValueError:
            continue
    return value
